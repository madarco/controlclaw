//! The brain's counts for the console's Brain Overview (`gbrain-stats.ts`,
//! docs/plans/brain-overview-charts.md): how many pages it holds and how many of each kind.
//! Numbers and GBrain's own type names only, never a page. Read from GBrain's
//! `GET /admin/api/full-stats` over loopback with the admin cookie the activity reader holds.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::sync::LazyLock;
use std::time::Duration;

use serde_json::{Map, Value, json};

/// The page types that may reach the console by name: the ones GBrain's built-in schema pack
/// `gbrain-base` declares (v0.60.10.0). A page's type comes from its frontmatter, which an agent
/// writes, so any other name could be text from the brain; every other type is counted in `other`.
pub const BASE_PAGE_TYPES: &[&str] = &[
    "person",
    "company",
    "deal",
    "yc",
    "civic",
    "project",
    "concept",
    "source",
    "media",
    "writing",
    "analysis",
    "guide",
    "hardware",
    "architecture",
    "meeting",
    "note",
    "email",
    "slack",
    "calendar-event",
    "conversation",
    "atom",
    "event",
    "diary",
    "code",
    "image",
    "synthesis",
    "extract_receipt",
];
static BASE: LazyLock<HashSet<&'static str>> = LazyLock::new(|| BASE_PAGE_TYPES.iter().copied().collect());
pub const STATS_EVERY: Duration = Duration::from_secs(15 * 60);

/// A count, or `None`. Postgres `count(*)` arrives as a string through some drivers.
fn count(v: Option<&Value>) -> Option<u64> {
    let n = match v? {
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s.parse::<f64>().ok()?,
        Value::Number(n) => n.as_f64()?,
        _ => return None,
    };
    (n.is_finite() && n >= 0.0).then(|| n.round() as u64)
}

/// Pages per base type, and every other type summed into `other` (never sent by name).
pub fn type_counts(raw: Option<&Value>) -> Map<String, Value> {
    let mut out: Map<String, Value> = Map::new();
    let Some(Value::Object(m)) = raw else { return out };
    for (k, v) in m {
        let Some(n) = count(Some(v)).filter(|n| *n > 0) else {
            continue;
        };
        let name = if BASE.contains(k.as_str()) { k.as_str() } else { "other" };
        let prev = out.get(name).and_then(Value::as_u64).unwrap_or(0);
        out.insert(name.into(), json!(prev + n));
    }
    out
}

/// The volume GBrain's data is on, as `df` counts it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Disk {
    pub used: u64,
    pub free: u64,
}

/// GBrain's stats body as a record; `None` when it is not stats (an error body, no page count).
pub fn map_brain_stats(body: &Value, now_ms: i64, disk: Option<Disk>) -> Option<Value> {
    let b = body.as_object()?;
    let pages = count(b.get("page_count"))?;
    Some(json!({
        "source": "brain_stats",
        "ts": now_ms.div_euclid(1000),
        "page_count": pages,
        "chunk_count": count(b.get("chunk_count")).unwrap_or(0),
        "embedded_count": count(b.get("embedded_count")),
        "link_count": count(b.get("link_count")),
        "tag_count": count(b.get("tag_count")),
        "timeline_entry_count": count(b.get("timeline_entry_count")),
        "pages_by_type": type_counts(b.get("pages_by_type")),
        "disk_used_bytes": disk.map(|d| d.used),
        "disk_free_bytes": disk.map(|d| d.free),
    }))
}

/// The fullest of the volumes behind `paths`: the blocks in use, and what a service may still
/// write (ext4's root reserve is in neither). `None` when none can be read.
pub fn brain_disk(paths: &[&std::path::Path]) -> Option<Disk> {
    let mut seen = HashSet::new();
    let mut fullest: Option<Disk> = None;
    for path in paths {
        let Ok(meta) = std::fs::metadata(path) else { continue };
        if !seen.insert(meta.dev()) {
            continue;
        }
        let Ok(s) = rustix::fs::statvfs(*path) else { continue };
        let used = (s.f_blocks - s.f_bfree) * s.f_frsize;
        let free = s.f_bavail * s.f_frsize;
        if used + free == 0 {
            continue;
        }
        let ratio = |d: Disk| d.used as f64 / (d.used + d.free) as f64;
        let d = Disk { used, free };
        if fullest.is_none_or(|f| ratio(d) > ratio(f)) {
            fullest = Some(d);
        }
    }
    fullest
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const FULL: &str = r#"{"status":"ok","version":"0.60.10.0","engine":"postgres","page_count":10000,"chunk_count":10000,"embedded_count":0,"link_count":0,"tag_count":20,"timeline_entry_count":0,"pages_by_type":{"project":2022,"person":1606,"company":911}}"#;

    #[test]
    fn stats_become_a_record_of_counts_and_type_names() {
        let full: Value = serde_json::from_str(FULL).expect("json");
        let r = map_brain_stats(&full, 1_760_000_000_500, None).expect("record");
        assert_eq!(
            r,
            json!({
                "source": "brain_stats", "ts": 1_760_000_000i64, "page_count": 10000, "chunk_count": 10000,
                "embedded_count": 0, "link_count": 0, "tag_count": 20, "timeline_entry_count": 0,
                "pages_by_type": {"project": 2022, "person": 1606, "company": 911},
                "disk_used_bytes": null, "disk_free_bytes": null,
            })
        );
        let with_disk = map_brain_stats(
            &full,
            0,
            Some(Disk {
                used: 1_300_000_000,
                free: 38_700_000_000,
            }),
        )
        .expect("r");
        assert_eq!(with_disk["disk_used_bytes"], 1_300_000_000u64);
        assert!(r.get("version").is_none());
    }

    #[test]
    fn an_error_body_or_no_page_count_is_not_a_record() {
        assert!(map_brain_stats(&json!({"error": "service_unavailable"}), 0, None).is_none());
        assert!(map_brain_stats(&Value::Null, 0, None).is_none());
        assert!(map_brain_stats(&json!([1, 2]), 0, None).is_none());
        assert!(map_brain_stats(&json!({"page_count": -1}), 0, None).is_none());
    }

    #[test]
    fn counts_as_strings_are_read_and_missing_ones_are_null() {
        let r = map_brain_stats(
            &json!({"page_count": "12", "chunk_count": "30", "pages_by_type": {"note": "12"}}),
            0,
            None,
        )
        .expect("r");
        assert_eq!(r["page_count"], 12);
        assert_eq!(r["chunk_count"], 30);
        assert_eq!(r["tag_count"], Value::Null);
        assert_eq!(r["pages_by_type"], json!({"note": 12}));
    }

    #[test]
    fn only_base_types_by_name() {
        let out = type_counts(Some(
            &json!({"person": 3, "meeting": 2, "acme-merger-secret": 4, "Person": 1, "other": 2, "empty": 0, "bad": "nope"}),
        ));
        assert_eq!(
            Value::Object(out.clone()),
            json!({"person": 3, "meeting": 2, "other": 7})
        );
        assert!(!serde_json::to_string(&out).expect("s").contains("acme"));
        assert_eq!(BASE.len(), BASE_PAGE_TYPES.len());
        assert!(BASE_PAGE_TYPES.len() < 30, "the console takes at most 30 types");
        assert!(type_counts(None).is_empty());
    }

    #[test]
    fn the_fullest_disk_and_missing_paths_left_out() {
        let d = brain_disk(&[std::path::Path::new("/"), std::path::Path::new("/nonexistent-cc-path")]).expect("disk");
        assert!(d.used > 0);
        assert!(brain_disk(&[std::path::Path::new("/nonexistent-cc-path")]).is_none());
    }
}
