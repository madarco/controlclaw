//! Telling the owner that the recovery key was used (`recovery-notices.ts`, T-99). A change
//! confirmed with the recovery key went through because no channel could reach anyone, so the owner
//! is told once a channel works again: each notice is kept, sealed under the box key, and retried
//! every five minutes until an agent box delivers it to an approved person.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::agent_client::{AgentClient, AgentTarget};
use super::code_message::clean_line;
use super::consent::{RecoveryConfirm, iso};
use super::kit::Kit;
use super::now_ms;
use super::own_messages::remember_own;
use crate::contracts::CodeSender;

pub const NOTICE_RETRY_MS: u64 = 5 * 60_000;
/// A notice nobody could be sent in a month is not news any more.
const NOTICE_TTL_MS: u64 = 30 * 24 * 60 * 60_000;
const MAX_NOTICES: usize = 20;

#[derive(Debug, Clone, PartialEq)]
struct Notice {
    subject: String,
    summary: String,
    at: u64,
}

/// `brief`: cleaned to one line, cut at `max` characters with an ellipsis.
fn brief(text: &str, max: usize) -> String {
    let (clean, _) = clean_line(text);
    let chars: Vec<char> = clean.chars().collect();
    if chars.len() > max {
        format!("{}…", chars[..max].iter().collect::<String>().trim_end())
    } else {
        clean
    }
}

/// `noticeText`: the firewall's own words first, then the change as it was described.
fn notice_text(n: &Notice) -> String {
    let when = iso(n.at).chars().take(16).collect::<String>().replacen('T', " ", 1);
    format!(
        "ControlClaw: a change was confirmed with your recovery key on {when} UTC, because no channel could reach you.\n\
         If that was not you, somebody else has your recovery key. Make a new one in Settings → Backups and check your ControlClaw console.\n\n\
         The change, as it was described then: {} ({})",
        brief(&n.summary, 500),
        brief(&n.subject, 80)
    )
}

pub type PublicKey = Arc<dyn Fn() -> Option<String> + Send + Sync>;

struct Inner {
    path: PathBuf,
    box_key: String,
    aad: String,
    notices: Mutex<Vec<Notice>>,
    agent: AgentClient,
    kit: Kit,
    public_key: PublicKey,
    /// One delivery run at a time.
    running: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
pub struct RecoveryNotices(Arc<Inner>);

impl RecoveryNotices {
    pub fn new(
        path: PathBuf,
        box_key: &str,
        org: &str,
        box_id: &str,
        agent: AgentClient,
        kit: Kit,
        public_key: PublicKey,
    ) -> Self {
        let aad = format!("{org}:{box_id}:recovery-notices");
        let log = |l: &str| tracing::error!("{l}");
        let notices = match cc_crypto::enc_file::load_store_or_empty("recovery-notices", &path, box_key, &aad, &log) {
            Some(v) if v.get("version").and_then(Value::as_f64) == Some(1.0) => v
                .get("notices")
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .map(|n| Notice {
                            subject: n.get("subject").and_then(Value::as_str).unwrap_or_default().into(),
                            summary: n.get("summary").and_then(Value::as_str).unwrap_or_default().into(),
                            at: n.get("at").and_then(Value::as_f64).unwrap_or(0.0) as u64,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        Self(Arc::new(Inner {
            path,
            box_key: box_key.into(),
            aad,
            notices: Mutex::new(notices),
            agent,
            kit,
            public_key,
            running: tokio::sync::Mutex::new(()),
        }))
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let n = self.notices();
        self.save(&n);
    }

    fn notices(&self) -> std::sync::MutexGuard<'_, Vec<Notice>> {
        self.0.notices.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, notices: &[Notice]) {
        let v = json!({"version": 1, "notices": notices.iter().map(|n| json!({"subject": n.subject, "summary": n.summary, "at": n.at})).collect::<Vec<_>>()});
        if let Err(e) =
            cc_crypto::enc_file::save_store("recovery-notices", &self.0.path, &v, &self.0.box_key, &self.0.aad)
        {
            tracing::error!("[recovery-notices] could not save the store: {e}");
        }
    }

    #[allow(dead_code)] // the tests
    pub fn pending(&self) -> usize {
        self.notices().len()
    }

    /// Deliver every waiting notice: on the retry timer, and right after a `used`.
    pub async fn tick(&self) {
        if self.notices().is_empty() {
            return;
        }
        let _one = self.0.running.lock().await;
        let cutoff = now_ms().saturating_sub(NOTICE_TTL_MS);
        let waiting = self.notices().clone();
        let mut done = Vec::new();
        for n in waiting {
            if n.at < cutoff || self.deliver(&notice_text(&n)).await {
                done.push(n);
            }
        }
        // Filtered rather than replaced: a `used` that landed meanwhile is kept.
        if !done.is_empty() {
            // One occurrence each: a `used` that landed meanwhile with the same fields stays.
            let mut list = self.notices();
            for d in &done {
                if let Some(i) = list.iter().position(|n| n == d) {
                    list.remove(i);
                }
            }
            self.save(&list);
        }
    }

    /// The first real person an agent box can reach; never the dev route.
    async fn deliver(&self, text: &str) -> bool {
        let routes = self.0.kit.routes().unwrap_or_default();
        for route in routes {
            for sender in &route.senders {
                let CodeSender::Person { kind, id, label } = sender else {
                    continue;
                };
                remember_own(text);
                let target = AgentTarget::new(&route.vm_id, &route.hostname);
                let body = json!({"type": kind, "to": id, "text": text});
                if self.0.agent.post(&target, "/channels/send", &body).await.is_ok() {
                    tracing::info!(
                        "[recovery-notices] told {kind}:{} that the recovery key was used",
                        label.as_deref().unwrap_or(id)
                    );
                    return true;
                }
            }
        }
        false
    }
}

impl RecoveryConfirm for RecoveryNotices {
    fn public_key(&self) -> Option<String> {
        (self.0.public_key)()
    }

    fn used(&self, subject: &str, summary: &str, at_ms: u64) {
        {
            let mut list = self.notices();
            list.push(Notice {
                subject: subject.into(),
                summary: summary.into(),
                at: at_ms,
            });
            let skip = list.len().saturating_sub(MAX_NOTICES);
            list.drain(..skip);
            self.save(&list);
        }
        tracing::info!(
            "[recovery-notices] \"{summary}\" was confirmed with the recovery key; the owner is told when a channel answers"
        );
        let me = self.clone();
        tokio::spawn(async move { me.tick().await });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text() {
        let n = Notice {
            subject: "atlas".into(),
            summary: "Update the software on atlas".into(),
            at: 1_790_000_000_000,
        };
        let t = notice_text(&n);
        assert!(t.starts_with("ControlClaw: a change was confirmed with your recovery key on 2026-09-21 "));
        assert!(t.ends_with("The change, as it was described then: Update the software on atlas (atlas)"));
        assert_eq!(brief(&"x".repeat(10), 4), "xxxx…");
    }
}
