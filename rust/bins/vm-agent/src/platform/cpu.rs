//! CPU use for the meters on the agent page (`cpu-sampler.ts`). The first line of `/proc/stat` is
//! read every 10 s and the last two readings kept; the use is what was not idle between them.
//! `load1 / cpus` is not this: load passes 100% and counts processes waiting on disk.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

pub const CPU_SAMPLE: Duration = Duration::from_secs(10);
/// Windows in a row without a number before "not yet" becomes "cannot read".
pub const CPU_MISSED_WINDOWS: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuSample {
    /// Jiffies spent idle or waiting on disk, all cores together.
    pub idle: f64,
    pub total: f64,
}

/// `cpu  user nice system idle iowait irq softirq steal guest guest_nice`. Guest time is already
/// inside user and nice, so the total stops at steal. None for anything that is not that line.
pub fn parse_proc_stat(text: &str) -> Option<CpuSample> {
    let line = text.split('\n').next().unwrap_or_default();
    let rest = line.strip_prefix("cpu")?;
    if !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let n: Vec<f64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|v| v.parse::<f64>().unwrap_or(f64::NAN))
        .collect();
    if n.len() < 4 || n.iter().any(|v| !v.is_finite() || *v < 0.0) {
        return None;
    }
    Some(CpuSample {
        idle: n[3] + n.get(4).copied().unwrap_or(0.0),
        total: n.iter().sum(),
    })
}

/// Percent of the time between two readings that was not idle; None when the counter did not move.
pub fn cpu_pct(prev: CpuSample, next: CpuSample) -> Option<f64> {
    let total = next.total - prev.total;
    if total.is_nan() || total <= 0.0 {
        return None;
    }
    let busy = 1.0 - (next.idle - prev.idle) / total;
    Some((busy.clamp(0.0, 1.0) * 1000.0).round() / 10.0)
}

#[derive(Default)]
struct Window {
    prev: Option<(CpuSample, Instant)>,
    last: Option<(CpuSample, Instant)>,
    samples: u64,
    missed: u32,
}

impl Window {
    fn use_(&self) -> Option<(f64, i64)> {
        let ((p, pa), (l, la)) = (self.prev?, self.last?);
        let used = cpu_pct(p, l)?;
        Some((used, (la.duration_since(pa).as_secs_f64() * 1000.0).round() as i64))
    }
}

/// The two-reading window. A reading that fails empties it. The clock only goes forward, so a
/// clock step (NTP, a suspend) cannot stretch or shrink the window.
pub struct CpuSampler {
    read: Box<dyn Fn() -> Option<String> + Send + Sync>,
    w: Mutex<Window>,
}

impl CpuSampler {
    pub fn new(read: impl Fn() -> Option<String> + Send + Sync + 'static) -> Self {
        Self {
            read: Box::new(read),
            w: Mutex::new(Window::default()),
        }
    }

    pub fn proc_stat() -> Self {
        Self::new(|| std::fs::read_to_string("/proc/stat").ok())
    }

    pub fn sample(&self) {
        let s = (self.read)().and_then(|t| parse_proc_stat(&t));
        let mut w = super::common::lock(&self.w);
        w.prev = if s.is_some() { w.last } else { None };
        w.last = s.map(|s| (s, Instant::now()));
        w.samples += 1;
        // The first reading closes no window, so it cannot miss one.
        if w.samples > 1 {
            w.missed = if w.use_().is_some() { 0 } else { w.missed + 1 };
        }
    }

    pub fn used_pct(&self) -> Option<f64> {
        super::common::lock(&self.w).use_().map(|u| u.0)
    }

    /// What the summary carries: the use, null while the second reading has not been taken yet,
    /// or `{unavailable: true}` once two windows in a row gave no number.
    pub fn report(&self) -> Value {
        let w = super::common::lock(&self.w);
        match w.use_() {
            Some((used, ms)) => json!({ "usedPct": super::common::js_number(used), "windowMs": ms }),
            None if w.missed >= CPU_MISSED_WINDOWS => json!({ "unavailable": true }),
            None => Value::Null,
        }
    }

    /// Reads now and every 10 s from here on.
    pub fn start(self: &Arc<Self>) {
        self.sample();
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut every = tokio::time::interval(CPU_SAMPLE);
            every.tick().await;
            loop {
                every.tick().await;
                let Some(me) = me.upgrade() else { return };
                me.sample();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_first_line_only_up_to_steal() {
        let s = parse_proc_stat("cpu  10 0 10 70 10 0 0 0 99 99\ncpu0 1 2 3 4\n").expect("line");
        assert_eq!(
            s,
            CpuSample {
                idle: 80.0,
                total: 100.0
            }
        );
        assert!(parse_proc_stat("cpu0 1 2 3 4").is_none());
        assert!(parse_proc_stat("cpu 1 2 x 4").is_none());
        assert!(parse_proc_stat("cpu 1 2 3").is_none());
        assert!(parse_proc_stat("").is_none());
    }

    #[test]
    fn use_is_what_was_not_idle() {
        let a = CpuSample {
            idle: 80.0,
            total: 100.0,
        };
        assert_eq!(
            cpu_pct(
                a,
                CpuSample {
                    idle: 110.0,
                    total: 200.0
                }
            ),
            Some(70.0)
        );
        assert_eq!(cpu_pct(a, a), None);
    }

    #[test]
    fn null_then_a_use_then_unavailable_after_two_misses() {
        let n = Arc::new(Mutex::new(0u32));
        let c = n.clone();
        let s = CpuSampler::new(move || {
            let mut i = c.lock().expect("l");
            *i += 1;
            match *i {
                1 => Some("cpu 0 0 0 100 0".into()),
                2 => Some("cpu 50 0 0 150 0".into()),
                _ => None,
            }
        });
        s.sample();
        assert_eq!(s.report(), Value::Null);
        s.sample();
        assert_eq!(s.report()["usedPct"], json!(50));
        s.sample();
        assert_eq!(s.report(), Value::Null);
        s.sample();
        assert_eq!(s.report(), json!({ "unavailable": true }));
    }
}
