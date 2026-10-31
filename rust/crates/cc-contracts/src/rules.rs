//! `rules.json`: the organization's website rules, as the control plane's `egress-rules`
//! endpoint shapes them. The agent copies them through unchanged (index.ts `runSync`); the addon
//! reads them in `match_rule`, `tunnel_match`, `residential_rule` and the AI review.

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

/// One website rule. First match by ascending `priority` (default 1000) wins; no match allows.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub name: Maybe<String>,
    /// `allow`, `block`, `require_permission` or `tunnel` (addon default: `allow`).
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub effect: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub priority: Maybe<Num>,
    /// Exact, `*`, or `*.example.com`. Missing means `*` for `match_rule`.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub match_domain: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub match_method: Maybe<String>,
    /// A substring of the path.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub match_path: Maybe<String>,
    /// For `tunnel` and residential rules; raw TCP is matched by IP and this port.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub match_port: Maybe<Num>,
    /// A rule with a vm_id applies to that agent only; without, to every agent.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub vm_id: Maybe<String>,
    /// `residential` sends matching connections out through the org's upstream proxy.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub exit: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub exit_country: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub ai_review: Maybe<bool>,
    /// The admin's note for the AI: approval policy on an Ask rule, instructions on an Allow rule.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub ai_policy: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

pub type RulesFile = Vec<Rule>;
