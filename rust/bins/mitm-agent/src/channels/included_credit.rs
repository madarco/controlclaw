//! Tells the control plane when ControlClaw's own AI Gateway account has run out of credit
//! (`included-credit.ts`, apps/saas/docs/features/included-ai-tokens.md).
//!
//! The proxy classifies the gateway's answers on the traffic record: `included: "no_credit"` means
//! the gateway refused on OUR account, `included: "ok"` is a call that went through. This counts
//! them and puts one line on the heartbeat; recovery is said at once.
//!
//! The records come from the activity shipper (W3's `onShipped`), which calls [`IncludedCreditWatch::note`].

use std::sync::Mutex;

use cc_crypto::store_health::iso_from_millis;
use serde_json::{Map, Value, json};

use crate::commands::CommandResult;

/// At most one report per firewall per window, however many refusals land in it.
pub const REPORT_INTERVAL_MS: i64 = 5 * 60_000;

#[derive(Default)]
struct State {
    seen: u64,
    first_at: Option<i64>,
    last_at: Option<i64>,
    reported_at: i64,
    outstanding: bool,
    recovered: bool,
}

pub struct IncludedCreditWatch {
    state: Mutex<State>,
    now: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl Default for IncludedCreditWatch {
    fn default() -> Self {
        Self::new(Box::new(super::now_ms))
    }
}

impl IncludedCreditWatch {
    pub fn new(now: Box<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            now,
        }
    }

    /// Walk one shipped batch in the order the proxy wrote it. A success wipes the refusals still
    /// waiting to be reported.
    pub fn note(&self, records: &[Value]) {
        let now = (self.now)();
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for r in records {
            let Some(o) = r.as_object() else { continue };
            match o.get("included").and_then(Value::as_str) {
                Some("no_credit") => {
                    s.recovered = false;
                    let at = match o.get("ts").and_then(Value::as_f64) {
                        Some(ts) if ts.is_finite() => (ts * 1000.0) as i64,
                        _ => now,
                    };
                    if s.first_at.is_none_or(|f| at < f) {
                        s.first_at = Some(at);
                    }
                    if s.last_at.is_none_or(|l| at > l) {
                        s.last_at = Some(at);
                    }
                    s.seen += 1;
                    if s.seen == 1 {
                        tracing::info!("[included] the AI gateway refused a call for lack of credit on our account");
                    }
                }
                Some("ok") => {
                    s.seen = 0;
                    s.first_at = None;
                    s.last_at = None;
                    if s.outstanding && !s.recovered {
                        s.recovered = true;
                        tracing::info!("[included] the AI gateway is answering again");
                    }
                }
                _ => {}
            }
        }
    }

    /// The line for this beat, or nothing. Rate-limited, not drained.
    pub fn drain_reports(&self) -> Vec<CommandResult> {
        let now = (self.now)();
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.recovered {
            s.recovered = false;
            s.outstanding = false;
            s.reported_at = now;
            return vec![CommandResult {
                command_id: format!("included.recovered:{}", now.div_euclid(1000)),
                ok: true,
                status: "gateway_recovered".into(),
                message: "The AI Gateway is answering included-tokens calls again.".into(),
                data: Some(Map::new()),
            }];
        }
        if s.seen == 0 || now - s.reported_at < REPORT_INTERVAL_MS {
            return vec![];
        }
        let seen = s.seen;
        let (first_at, last_at) = (s.first_at, s.last_at);
        s.reported_at = now;
        s.outstanding = true;
        s.seen = 0;
        s.first_at = None;
        s.last_at = None;
        let mut data = Map::new();
        data.insert("seen".into(), json!(seen));
        // `firstAt ? …` in the TS: a zero timestamp is left out too.
        if let Some(f) = first_at.filter(|f| *f != 0) {
            data.insert("firstAt".into(), json!(iso_from_millis(f)));
        }
        if let Some(l) = last_at.filter(|l| *l != 0) {
            data.insert("lastAt".into(), json!(iso_from_millis(l)));
        }
        vec![CommandResult {
            command_id: format!("included.no-credit:{}", now.div_euclid(1000)),
            ok: false,
            status: "gateway_no_credit".into(),
            message: format!(
                "The AI Gateway refused {seen} included-tokens call(s) for lack of credit on ControlClaw's account."
            ),
            data: Some(data),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    fn watch() -> (IncludedCreditWatch, Arc<AtomicI64>) {
        let clock = Arc::new(AtomicI64::new(1_700_000_000_000));
        let c = clock.clone();
        (
            IncludedCreditWatch::new(Box::new(move || c.load(Ordering::SeqCst))),
            clock,
        )
    }

    fn no_credit(ts: Option<i64>) -> Value {
        let mut v = json!({"flow_id": "f", "host": "ai-gateway.vercel.sh", "included": "no_credit"});
        if let Some(ts) = ts {
            v["ts"] = json!(ts);
        }
        v
    }

    fn ok() -> Value {
        json!({"flow_id": "s", "host": "ai-gateway.vercel.sh", "included": "ok"})
    }

    fn seen(r: &CommandResult) -> u64 {
        r.data
            .as_ref()
            .and_then(|d| d.get("seen"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }

    #[test]
    fn nothing_to_report_without_a_refusal() {
        let (w, _) = watch();
        w.note(&[
            json!({"flow_id": "a", "host": "api.github.com", "status": 200}),
            json!({"flow_id": "b", "included": "used_up"}),
        ]);
        assert!(w.drain_reports().is_empty());
        w.note(&[json!({"flow_id": "b", "included": "used_up"})]);
        assert!(
            w.drain_reports().is_empty(),
            "the organisation's own budget is not ours"
        );
    }

    #[test]
    fn one_refusal_one_report_many_counted() {
        let (w, _) = watch();
        w.note(&[no_credit(None)]);
        let r = w.drain_reports();
        assert!(r[0].command_id.starts_with("included.no-credit:"));
        assert!(!r[0].ok);
        assert_eq!(r[0].status, "gateway_no_credit");
        assert_eq!(seen(&r[0]), 1);

        let (w, _) = watch();
        w.note(&[no_credit(None), no_credit(None)]);
        w.note(&[no_credit(None)]);
        let r = w.drain_reports();
        assert_eq!(r.len(), 1);
        assert_eq!(seen(&r[0]), 3);
    }

    #[test]
    fn the_report_carries_when() {
        let (w, _) = watch();
        w.note(&[no_credit(Some(1_700_000_100)), no_credit(Some(1_700_000_050))]);
        let r = w.drain_reports();
        let d = r[0].data.clone().expect("data");
        assert_eq!(d["firstAt"], json!(iso_from_millis(1_700_000_050_000)));
        assert_eq!(d["lastAt"], json!(iso_from_millis(1_700_000_100_000)));
    }

    #[test]
    fn windows() {
        let (w, clock) = watch();
        w.note(&[no_credit(None)]);
        assert_eq!(w.drain_reports().len(), 1);
        w.note(&[no_credit(None)]);
        assert!(w.drain_reports().is_empty(), "still inside the window");
        clock.fetch_add(REPORT_INTERVAL_MS, Ordering::SeqCst);
        let second = w.drain_reports();
        assert_eq!(second.len(), 1);
        assert_eq!(seen(&second[0]), 1);
        clock.fetch_add(REPORT_INTERVAL_MS * 3, Ordering::SeqCst);
        assert!(w.drain_reports().is_empty(), "a quiet window stays quiet");
    }

    #[test]
    fn recovery() {
        let (w, clock) = watch();
        w.note(&[no_credit(None), no_credit(None), ok()]);
        assert!(w.drain_reports().is_empty(), "a success wipes unreported refusals");

        w.note(&[no_credit(None)]);
        assert_eq!(w.drain_reports()[0].status, "gateway_no_credit");
        w.note(&[ok()]);
        let r = w.drain_reports();
        assert_eq!(r.len(), 1, "recovery does not wait out the window");
        assert!(r[0].command_id.starts_with("included.recovered:"));
        assert!(r[0].ok);
        assert_eq!(r[0].status, "gateway_recovered");
        w.note(&[ok(), ok()]);
        assert!(w.drain_reports().is_empty(), "said once");

        let (w2, _) = watch();
        w2.note(&[ok(), ok(), ok()]);
        assert!(w2.drain_reports().is_empty());

        clock.fetch_add(REPORT_INTERVAL_MS, Ordering::SeqCst);
        w.note(&[no_credit(None), no_credit(None)]);
        let r = w.drain_reports();
        assert_eq!(r[0].status, "gateway_no_credit");
        assert_eq!(seen(&r[0]), 2);
    }

    #[test]
    fn a_batch_ending_in_refusals_after_a_success_reports_them() {
        let (w, _) = watch();
        w.note(&[no_credit(None), ok(), no_credit(None)]);
        let r = w.drain_reports();
        assert_eq!(r[0].status, "gateway_no_credit");
        assert_eq!(seen(&r[0]), 1);
    }

    #[test]
    fn junk_is_ignored() {
        let (w, _) = watch();
        w.note(&[Value::Null, json!("x"), json!(7), json!({"included": 402})]);
        assert!(w.drain_reports().is_empty());
    }
}
