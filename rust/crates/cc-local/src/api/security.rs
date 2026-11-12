//! Auto approve rules: what the firewall answers an agent's permission request with. They live on
//! the firewall, like the app rules: a read is `autoapprove.read`, a change `autoapprove.propose`,
//! applied at once for the signed-in admin ([`super::Ctx::apply`]). The counts the Security rules
//! tab shows ("12 in 7 days") are this database's `rule_hourly`, bumped when the firewall reports
//! what its rules decided (`plane.rs`).

use http::Method;
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::rules::{ChangeBody, change};
use super::{CommandAnswer, Reply, Route, data_of};
use crate::db::{Db, now_s};

const TAG: &str = "rules";

/// The grey row's name, as the console's (`DEFAULT_NAMES.auto`).
const DEFAULT_NAME: &str = "Every other request";

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), Value, _, _>(
            "/api/security/rules",
            TAG,
            "The Auto approve rules, first match wins (`autoapprove.read`)",
            |c| async move { Ok(Reply::ok(&data_of(c.command("autoapprove.read", json!({})).await?)?)) },
        ),
        Route::write::<ChangeBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/security/rules/change",
            TAG,
            "Add or change an Auto approve rule (`{op: put, rule, at?}`), delete one (`{op: delete, id}`), or move one (`{op: move, id, to}`)",
            |c, b| async move { change(&c, "autoapprove", b.change).await },
        ),
        Route::get::<MetricsQuery, RuleMetrics, _, _>(
            "/api/rule-metrics",
            TAG,
            "How often each Auto approve rule, and Every other request, matched in a range: by agent with `agentId`",
            |c| async move {
                let q: MetricsQuery = c.query()?;
                let items = rule_activity(&c.db, q.range, q.agent_id.as_deref(), now_s())
                    .map_err(|e| Reply::error(500, e.to_string()))?;
                Ok(Reply::ok(&RuleMetrics {
                    items,
                    generated_at: crate::plane::iso(now_s()),
                }))
            },
        ),
    ]
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum MetricRange {
    #[serde(rename = "24h")]
    Day,
    #[default]
    #[serde(rename = "7d")]
    Week,
    #[serde(rename = "30d")]
    Month,
}

impl MetricRange {
    fn hours(self) -> i64 {
        match self {
            Self::Day => 24,
            Self::Week => 168,
            Self::Month => 720,
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MetricsQuery {
    #[serde(default)]
    pub range: MetricRange,
    /// One agent's matches only.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// What happened each time, as the console's `RuleCounts`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, JsonSchema)]
pub struct RuleCounts {
    pub allowed: i64,
    pub asked: i64,
    pub held: i64,
    pub blocked: i64,
    pub recorded: i64,
}

/// One rule's matches in the range, as the console's `RuleActivityItem`.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleActivity {
    /// Always `auto` here.
    #[serde(rename = "type")]
    pub rule_type: String,
    /// The rule's id, or `default` for Every other request.
    pub key: String,
    pub rule_id: Option<String>,
    pub name: String,
    pub builtin: bool,
    /// The panel tells a deleted rule by the list it read; always false here.
    pub deleted: bool,
    pub counts: RuleCounts,
    pub total: i64,
    /// The newest match in the range.
    pub last_at: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleMetrics {
    pub items: Vec<RuleActivity>,
    pub generated_at: String,
}

/// The Auto approve counts since the top of the hour `range` ago, busiest first.
pub fn rule_activity(
    db: &Db,
    range: MetricRange,
    agent: Option<&str>,
    now: i64,
) -> rusqlite::Result<Vec<RuleActivity>> {
    let since = now - now.rem_euclid(3600) - (range.hours() - 1) * 3600;
    let c = db.lock();
    let mut q = c.prepare(
        "SELECT rule_key, outcome, sum(count), max(last_at),
                (SELECT name FROM rule_hourly n WHERE n.rule_type = 'auto' AND n.rule_key = h.rule_key
                   AND n.name IS NOT NULL ORDER BY n.last_at DESC LIMIT 1)
         FROM rule_hourly h
         WHERE rule_type = 'auto' AND hour >= ?1 AND (?2 IS NULL OR vm_id = ?2)
         GROUP BY rule_key, outcome",
    )?;
    let rows: Vec<(String, String, i64, i64, Option<String>)> = q
        .query_map(params![since, agent], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut items: Vec<(RuleActivity, i64)> = Vec::new();
    for (key, outcome, n, last, name) in rows {
        let at = match items.iter().position(|(i, _)| i.key == key) {
            Some(i) => i,
            None => {
                let builtin = key == "default";
                items.push((
                    RuleActivity {
                        rule_type: "auto".into(),
                        rule_id: (!builtin).then(|| key.clone()),
                        name: if builtin {
                            DEFAULT_NAME.into()
                        } else {
                            name.unwrap_or_else(|| key.clone())
                        },
                        key,
                        builtin,
                        deleted: false,
                        counts: RuleCounts::default(),
                        total: 0,
                        last_at: String::new(),
                    },
                    0,
                ));
                items.len() - 1
            }
        };
        let (item, newest) = &mut items[at];
        match outcome.as_str() {
            "allowed" => item.counts.allowed += n,
            "blocked" => item.counts.blocked += n,
            "held" => item.counts.held += n,
            "recorded" => item.counts.recorded += n,
            _ => item.counts.asked += n,
        }
        item.total += n;
        *newest = (*newest).max(last);
    }
    let mut out: Vec<RuleActivity> = items
        .into_iter()
        .map(|(mut i, newest)| {
            i.last_at = crate::plane::iso(newest);
            i
        })
        .collect();
    out.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.key.cmp(&b.key)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_by_rule_in_the_range_and_by_agent() {
        let db = Db::memory().expect("db");
        let now = 2_000_000_000;
        {
            let c = db.lock();
            let add = |hour_ago: i64, vm: &str, key: &str, outcome: &str, n: i64, name: Option<&str>| {
                let at = now - hour_ago * 3600;
                c.execute(
                    "INSERT INTO rule_hourly (hour, vm_id, rule_type, rule_key, outcome, count, last_at, name)
                     VALUES (?1, ?2, 'auto', ?3, ?4, ?5, ?6, ?7)",
                    params![at - at.rem_euclid(3600), vm, key, outcome, n, at, name],
                )
                .expect("insert");
            };
            add(1, "oc1", "r1", "allowed", 3, Some("Allow git"));
            add(2, "oc2", "r1", "allowed", 2, Some("Allow git"));
            add(1, "oc1", "default", "asked", 1, None);
            add(30, "oc1", "r2", "blocked", 5, Some("Block rm"));
            add(24 * 9, "oc1", "r1", "allowed", 100, Some("Allow git"));
        }
        let day = rule_activity(&db, MetricRange::Day, None, now).expect("day");
        assert_eq!(day.len(), 2);
        assert_eq!(
            (day[0].key.as_str(), day[0].total, day[0].name.as_str()),
            ("r1", 5, "Allow git")
        );
        assert_eq!(
            (day[1].name.as_str(), day[1].builtin, day[1].rule_id.clone()),
            (DEFAULT_NAME, true, None)
        );
        let week = rule_activity(&db, MetricRange::Week, Some("oc1"), now).expect("week");
        assert_eq!(
            week.iter().map(|i| (i.key.as_str(), i.total)).collect::<Vec<_>>(),
            [("r2", 5), ("r1", 3), ("default", 1)]
        );
        assert_eq!(week[0].counts.blocked, 5);
        let month = rule_activity(&db, MetricRange::Month, None, now).expect("month");
        assert_eq!(month[0].total, 105);
    }
}
