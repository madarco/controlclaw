//! ISO 8601 times as JavaScript's `Date` writes and reads the ones the agent uses: UTC, `Z`,
//! milliseconds (`toISOString`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 for a civil date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `new Date(ms).toISOString()`.
pub fn iso_ms(ms: i64) -> String {
    cc_auth::firewall::chrono_like_iso(ms)
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64
}

pub fn now_iso() -> String {
    iso_ms(now_ms())
}

/// The ISO forms `date_parse` takes: a date, an optional time with any fraction, and `Z`, an
/// offset or neither.
static ISO: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"^([0-9]{4}-[0-9]{2}-[0-9]{2})(?:T([0-9]{2}:[0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?)?(Z|[+-][0-9]{2}:?[0-9]{2})?$",
    )
    .expect("regex")
});

/// `Date.parse` for ISO forms: any number of fraction digits (cut to ms), an offset or `Z`, or
/// none (UTC, the box's zone).
pub fn date_parse(s: &str) -> Option<i64> {
    let c = ISO.captures(s.trim())?;
    let frac = c.get(4).map_or("000".to_string(), |f| {
        format!("{:0<3}", &f.as_str()[..f.as_str().len().min(3)])
    });
    let canonical = format!(
        "{}T{}:{}.{frac}Z",
        &c[1],
        c.get(2).map_or("00:00", |m| m.as_str()),
        c.get(3).map_or("00", |m| m.as_str())
    );
    let at = parse_iso_z(&canonical)?;
    let offset = match c.get(5).map(|m| m.as_str()) {
        None | Some("Z") => 0,
        Some(o) => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let digits: String = o[1..].chars().filter(char::is_ascii_digit).collect();
            let (h, m): (i64, i64) = (digits[..2].parse().ok()?, digits[2..].parse().ok()?);
            sign * (h * 3_600_000 + m * 60_000)
        }
    };
    Some(at - offset)
}

/// Milliseconds for `YYYY-MM-DDTHH:MM:SS(.sss)?Z` exactly, the form the agent writes; it is also
/// used on text read from elsewhere, where any other form (six fraction digits, an offset) is None,
/// or for a date `Date` would not take (month 13, hour 25).
pub fn parse_iso_z(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = text.get(r)?;
        s.bytes().all(|c| c.is_ascii_digit()).then(|| s.parse().ok())?
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d, h, mi, s) = (
        digits(0..4)?,
        digits(5..7)?,
        digits(8..10)?,
        digits(11..13)?,
        digits(14..16)?,
        digits(17..19)?,
    );
    let rest = &text[19..];
    let milli = match rest {
        "Z" => 0,
        _ => {
            let frac = rest.strip_prefix('.')?.strip_suffix('Z')?;
            if frac.is_empty() || frac.len() > 3 || !frac.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            format!("{frac:0<3}").parse().ok()?
        }
    };
    let month_days = [
        31,
        if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            29
        } else {
            28
        },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo) || d < 1 || d > month_days[(mo - 1) as usize] || h > 24 || mi > 59 || s > 59 {
        return None;
    }
    if h == 24 && (mi != 0 || s != 0 || milli != 0) {
        return None;
    }
    Some(((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60_000 + s * 1000 + milli)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_like_date() {
        assert_eq!(iso_ms(0), "1970-01-01T00:00:00.000Z");
        let t = parse_iso_z("2026-10-12T09:30:00Z").expect("time");
        assert_eq!(iso_ms(t), "2026-10-12T09:30:00.000Z");
        assert_eq!(parse_iso_z("2026-10-12T09:30:00.5Z"), Some(t + 500));
        assert_eq!(
            parse_iso_z("2024-02-29T00:00:00Z").map(iso_ms).as_deref(),
            Some("2024-02-29T00:00:00.000Z")
        );
        for bad in [
            "2026-10-12",
            "2026-13-01T00:00:00Z",
            "2026-10-12T09:30:00+02:00",
            "2026-10-12T09:30:00.1234Z",
            "2025-02-29T00:00:00Z",
        ] {
            assert_eq!(parse_iso_z(bad), None, "{bad}");
        }
    }
}
