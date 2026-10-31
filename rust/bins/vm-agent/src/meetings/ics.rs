//! Calendar invites (.ics) mailed to the agent (`meeting-ics.ts`, docs/plans/meetjoin.md). Only
//! what the schedule needs is taken: when, the Meet link, a title.
//!
//! The TS reads the files with ical.js 2.2. This is the part of it the invites use, with its
//! behaviour where it matters:
//!
//! - Lines are unfolded and split into components, properties and parameters; text values are
//!   unescaped; `X-` properties keep their raw text.
//! - A time with a `TZID` uses the file's own `VTIMEZONE`, else one an earlier file registered
//!   (ical.js keeps a process-wide registry), else floating, which is the box's own zone: UTC on every
//!   box. `utcOffset` follows ical.js's change table, including its choice in a repeated hour.
//! - Recurrence: `RRULE` (DAILY, WEEKLY, MONTHLY, YEARLY with INTERVAL, COUNT, UNTIL, BYDAY with
//!   ordinals, BYMONTHDAY, BYMONTH, BYYEARDAY, BYSETPOS, BYHOUR, BYMINUTE, BYSECOND, WKST), `RDATE`,
//!   `EXDATE` (a date-only one removes the whole day). The first occurrence is the first time that
//!   matches the rule at or after `DTSTART`, as ical.js gives it. A date-only `UNTIL` is midnight,
//!   so later times that day are not included, as in ical.js.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};

use regex::Regex;

/// One occurrence the schedule may join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteOccurrence {
    /// `<uid>|<original start of this occurrence>`; `<uid>|` for an event that does not repeat.
    pub key: String,
    pub uid: String,
    pub start: i64,
    pub end: i64,
    pub url: String,
    pub title: String,
}

static MEET_LINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https://meet\.google\.com/[a-z]{3}-[a-z]{4}-[a-z]{3}").expect("regex"));
static CANONICAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^https://meet\.google\.com/[a-z]{3}-[a-z]{4}-[a-z]{3}$").expect("regex"));
const MAX_OCCURRENCES: usize = 2000;
pub const MAX_ICS_BYTES: usize = 256 * 1024;

/// The first Google Meet link in the texts, or `None`. Other conferencing links are not joined.
pub fn meet_link(texts: &[Option<&str>]) -> Option<String> {
    for text in texts.iter().flatten() {
        // `(?![a-z0-9-])` after the code: the regex crate has no lookahead, so check the next byte.
        let found = MEET_LINK.find_iter(text).find(|m| {
            !text[m.end()..]
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
        if let Some(m) = found {
            // `canonicalMeetUrl`: at most 200 characters and exactly the link.
            if m.as_str().len() <= 200 && CANONICAL.is_match(m.as_str()) {
                return Some(m.as_str().to_string());
            }
        }
    }
    None
}

// ---- Calendar time ----------------------------------------------------------------------------

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let (yy, mm) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Wall-clock fields, seconds since the epoch as if they were UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Civil(i64);

impl Civil {
    fn new(y: i64, m: i64, d: i64, h: i64, mi: i64, s: i64) -> Self {
        Civil(days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + s)
    }
    fn days(self) -> i64 {
        self.0.div_euclid(86_400)
    }
    fn secs_of_day(self) -> i64 {
        self.0.rem_euclid(86_400)
    }
    fn ymd(self) -> (i64, i64, i64) {
        civil_from_days(self.days())
    }
    fn year(self) -> i64 {
        self.ymd().0
    }
    /// 0 = Sunday.
    fn weekday(self) -> i64 {
        (self.days() + 4).rem_euclid(7)
    }
}

#[derive(Debug, Clone)]
enum Zone {
    Utc,
    /// No zone: the box's own, which is UTC on every box.
    Floating,
    Tz(Arc<Timezone>),
}

#[derive(Debug, Clone)]
struct Time {
    at: Civil,
    is_date: bool,
    zone: Zone,
}

impl Time {
    /// Seconds since the epoch (`toUnixTime`).
    fn unix(&self) -> i64 {
        let offset = match &self.zone {
            Zone::Utc | Zone::Floating => 0,
            Zone::Tz(tz) => tz.utc_offset(self.at),
        };
        self.at.0 - offset
    }
    fn unix_ms(&self) -> i64 {
        self.unix() * 1000
    }
    fn with(&self, at: Civil) -> Time {
        Time {
            at,
            is_date: self.is_date,
            zone: self.zone.clone(),
        }
    }
}

/// `new Date(ms).toISOString()`.
pub fn iso(ms: i64) -> String {
    cc_auth::firewall::chrono_like_iso(ms)
}

// ---- Parsing --------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Property {
    name: String,
    params: HashMap<String, String>,
    value: String,
}

#[derive(Debug, Clone, Default)]
struct Component {
    name: String,
    props: Vec<Property>,
    subs: Vec<Component>,
}

impl Component {
    fn first(&self, name: &str) -> Option<&Property> {
        self.props.iter().find(|p| p.name == name)
    }
    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> + 'a {
        self.props.iter().filter(move |p| p.name == name)
    }
    fn subs<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Component> + 'a {
        self.subs.iter().filter(move |c| c.name == name)
    }
}

/// `ICAL.parse`: unfolded lines into components. `None` where ical.js throws.
fn parse_components(text: &str) -> Option<Component> {
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if (raw.starts_with(' ') || raw.starts_with('\t')) && !lines.is_empty() {
            if let Some(last) = lines.last_mut() {
                last.push_str(&raw[1..]);
            }
        } else if !raw.is_empty() {
            lines.push(raw.to_string());
        }
    }
    let mut stack: Vec<Component> = Vec::new();
    let mut top: Option<Component> = None;
    for line in lines {
        let (head, value) = split_value(&line)?;
        let mut parts = split_params(head);
        let name = parts.remove(0).to_ascii_lowercase();
        if name.is_empty() {
            return None;
        }
        if name == "begin" {
            stack.push(Component {
                name: value.to_ascii_lowercase(),
                ..Default::default()
            });
            continue;
        }
        if name == "end" {
            let done = stack.pop()?;
            match stack.last_mut() {
                Some(parent) => parent.subs.push(done),
                None if top.is_none() => top = Some(done),
                None => {}
            }
            continue;
        }
        let mut params = HashMap::new();
        for p in parts {
            let (k, v) = p.split_once('=')?;
            params.insert(k.to_ascii_lowercase(), v.trim_matches('"').to_string());
        }
        // ical.js reads every RRULE as it parses the file: one it cannot read fails the file.
        if name == "rrule" && Rule::read(value).is_none() {
            return None;
        }
        let current = stack.last_mut()?;
        current.props.push(Property {
            name,
            params,
            value: value.to_string(),
        });
    }
    // Components left open still count, as ical.js keeps them.
    while let Some(done) = stack.pop() {
        match stack.last_mut() {
            Some(parent) => parent.subs.push(done),
            None if top.is_none() => top = Some(done),
            None => {}
        }
    }
    top
}

/// The name and parameters, and the value: the first `:` outside quotes.
fn split_value(line: &str) -> Option<(&str, &str)> {
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ':' if !quoted => return Some((&line[..i], &line[i + 1..])),
            _ => {}
        }
    }
    None
}

fn split_params(head: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut quoted, mut start) = (false, 0);
    for (i, c) in head.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.push(&head[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&head[start..]);
    out
}

/// TEXT values: `\n`, `\N`, `\,`, `\;`, `\\`. Any other backslash stays, as ical.js keeps it.
fn unescape(v: &str) -> String {
    let mut out = String::new();
    let mut chars = v.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('n' | 'N') => {
                chars.next();
                out.push('\n');
            }
            Some(e @ ('\\' | ';' | ',')) => {
                chars.next();
                out.push(e);
            }
            _ => out.push('\\'),
        }
    }
    out
}

const TEXT_PROPS: &[&str] = &["summary", "description", "location", "uid", "status", "method", "tzid"];

/// `String(getFirstPropertyValue(name) ?? "")`.
fn value(c: &Component, name: &str) -> String {
    match c.first(name) {
        Some(p) if TEXT_PROPS.contains(&name) => unescape(&p.value),
        Some(p) => p.value.clone(),
        None => String::new(),
    }
}

/// The process-wide zone registry (`ICAL.TimezoneService`): zones from earlier files stay.
static ZONES: LazyLock<Mutex<HashMap<String, Arc<Timezone>>>> = LazyLock::new(Mutex::default);

struct Calendar {
    method: String,
    events: Vec<Component>,
    zones: HashMap<String, Arc<Timezone>>,
}

fn parse(text: &str) -> Option<Calendar> {
    if text.encode_utf16().count() > MAX_ICS_BYTES {
        return None;
    }
    let calendar = parse_components(text)?;
    let mut zones = HashMap::new();
    for z in calendar.subs("vtimezone") {
        let id = value(z, "tzid");
        let tz = Arc::new(Timezone::new(z));
        ZONES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), tz.clone());
        zones.insert(id, tz);
    }
    let method = calendar
        .first("method")
        .map(|p| unescape(&p.value))
        .unwrap_or_else(|| "REQUEST".into())
        .to_uppercase();
    Some(Calendar {
        method,
        events: calendar.subs("vevent").cloned().collect(),
        zones,
    })
}

/// A DATE or DATE-TIME value (`Time.fromString`), in its zone.
fn parse_time(
    text: &str,
    tzid: Option<&str>,
    zones: &HashMap<String, Arc<Timezone>>,
    in_zone_rule: bool,
) -> Option<Time> {
    let t = text.trim();
    // A DATE (8), a DATE-TIME (15) or a UTC one (16); anything longer (a PERIOD) is not a time.
    if !matches!(t.len(), 8 | 15) && !(t.len() == 16 && t.ends_with('Z')) {
        return None;
    }
    let num = |a: usize, b: usize| {
        t.get(a..b)
            .filter(|s| s.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse::<i64>().ok())
    };
    let (y, m, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    if t.len() == 8 {
        return Some(Time {
            at: Civil::new(y, m, d, 0, 0, 0),
            is_date: true,
            zone: Zone::Floating,
        });
    }
    if t.as_bytes().get(8) != Some(&b'T') {
        return None;
    }
    let (h, mi, s) = (num(9, 11)?, num(11, 13)?, num(13, 15)?);
    let zone = if t.ends_with('Z') {
        Zone::Utc
    } else if in_zone_rule {
        Zone::Floating
    } else if let Some(id) = tzid {
        match zones.get(id) {
            Some(z) => Zone::Tz(z.clone()),
            None => match ZONES.lock().unwrap_or_else(|e| e.into_inner()).get(id) {
                Some(z) => Zone::Tz(z.clone()),
                None if matches!(id, "UTC" | "Z" | "GMT") => Zone::Utc,
                None => Zone::Floating,
            },
        }
    } else {
        Zone::Floating
    };
    Some(Time {
        at: Civil::new(y, m, d, h, mi, s),
        is_date: false,
        zone,
    })
}

fn prop_time(c: &Component, name: &str, zones: &HashMap<String, Arc<Timezone>>) -> Option<Time> {
    let p = c.first(name)?;
    let mut t = parse_time(&p.value, p.params.get("tzid").map(String::as_str), zones, false)?;
    if p.params.get("value").is_some_and(|v| v.eq_ignore_ascii_case("date")) && !t.is_date {
        t.is_date = true;
    }
    Some(t)
}

/// Every value of a list property (`RDATE`, `EXDATE`), in order.
/// A `PERIOD` value or one that is not a time is an error: ical.js gives it as something other
/// than a time and the expansion throws on it.
fn prop_times(c: &Component, name: &str, zones: &HashMap<String, Arc<Timezone>>) -> Result<Vec<Time>, String> {
    let mut out = Vec::new();
    for p in c.all(name) {
        for v in p.value.split(',') {
            match parse_time(v, p.params.get("tzid").map(String::as_str), zones, false) {
                Some(t) => out.push(t),
                None => return Err("next.toJSDate is not a function".into()),
            }
        }
    }
    out.sort_by_key(Time::unix);
    Ok(out)
}

/// `DURATION`: `[+-]P[nW][nD][T[nH][nM][nS]]`, in seconds.
fn parse_duration(v: &str) -> Option<i64> {
    static DURATION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^([+-])?P(?:([0-9]+)W)?(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+)S)?)?$")
            .expect("regex")
    });
    let c = DURATION.captures(v.trim())?;
    let n = |i: usize| c.get(i).map_or(0, |m| m.as_str().parse::<i64>().unwrap_or(0));
    let secs = n(2) * 7 * 86_400 + n(3) * 86_400 + n(4) * 3600 + n(5) * 60 + n(6);
    Some(if c.get(1).is_some_and(|m| m.as_str() == "-") {
        -secs
    } else {
        secs
    })
}

// ---- Time zones -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Change {
    /// The moment, as UTC wall-clock fields.
    utc: Civil,
    offset: i64,
    prev: i64,
    daylight: bool,
}

#[derive(Debug)]
pub struct Timezone {
    /// The STANDARD and DAYLIGHT observances.
    observances: Vec<Component>,
    /// The changes worked out so far, and the year they reach.
    changes: Mutex<(Vec<Change>, i64)>,
}

fn parse_offset(v: &str) -> Option<i64> {
    let v = v.trim();
    let sign = match v.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let n = |a: usize, b: usize| v.get(a..b).and_then(|s| s.parse::<i64>().ok());
    Some(sign * (n(1, 3)? * 3600 + n(3, 5)? * 60 + n(5, 7).unwrap_or(0)))
}

/// Changes are worked out this many years past the later of the time asked about and this year
/// (`Timezone.EXTRA_COVERAGE`).
const EXTRA_COVERAGE: i64 = 5;
/// A zone with more changes than this is cut off there. Real zones have two a year; this only
/// stops a file that repeats an observance daily from 1601 from eating the box's memory (ical.js
/// would grind through it).
const MAX_CHANGES: usize = 20_000;

fn this_year() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Civil(secs).year()
}

impl Timezone {
    fn new(c: &Component) -> Self {
        Timezone {
            observances: c
                .subs
                .iter()
                .filter(|s| s.name == "standard" || s.name == "daylight")
                .cloned()
                .collect(),
            changes: Mutex::new((Vec::new(), i64::MIN)),
        }
    }

    /// Every change up to the end of `until_year` (`_ensureCoverage`).
    fn expand(&self, until_year: i64) -> Vec<Change> {
        let mut changes = Vec::new();
        for obs in &self.observances {
            let (Some(start), Some(to), Some(from)) = (
                obs.first("dtstart"),
                obs.first("tzoffsetto").and_then(|p| parse_offset(&p.value)),
                obs.first("tzoffsetfrom").and_then(|p| parse_offset(&p.value)),
            ) else {
                continue;
            };
            let Some(dtstart) = parse_time(&start.value, None, &HashMap::new(), true) else {
                continue;
            };
            let daylight = obs.name == "daylight";
            let base = changes.len();
            let mut push = |at: Civil, utc: bool| {
                changes.push(Change {
                    utc: if utc { at } else { Civil(at.0 - from) },
                    offset: to,
                    prev: from,
                    daylight,
                })
            };
            if obs.first("rrule").is_none() && obs.first("rdate").is_none() {
                push(dtstart.at, false);
                continue;
            }
            for p in obs.all("rdate") {
                for v in p.value.split(',') {
                    if let Some(t) = parse_time(v, None, &HashMap::new(), false) {
                        let at = if t.is_date {
                            Civil(t.at.days() * 86_400 + dtstart.at.secs_of_day())
                        } else {
                            t.at
                        };
                        push(at, matches!(t.zone, Zone::Utc));
                    }
                }
            }
            if let Some(Ok(mut rule)) = obs.first("rrule").map(|p| Rule::parse(&p.value)) {
                // A UTC end is moved onto local time, as ical.js does.
                if let Some(u) = &mut rule.until
                    && matches!(u.zone, Zone::Utc)
                {
                    u.at = Civil(u.at.0 + from);
                    u.zone = Zone::Floating;
                }
                let mut it = RuleIter::new(rule, dtstart.clone());
                let mut added = 0;
                while let Some(occ) = it.next() {
                    if occ.at.year() > until_year || base + added >= MAX_CHANGES {
                        break;
                    }
                    push(occ.at, false);
                    added += 1;
                }
            }
        }
        changes.sort_by_key(|c| c.utc);
        changes
    }

    /// `Timezone.utcOffset(tt)` for wall-clock fields in this zone.
    fn utc_offset(&self, tt: Civil) -> i64 {
        let mut guard = self.changes.lock().unwrap_or_else(|e| e.into_inner());
        if guard.1 < tt.year() {
            let until = tt.year().max(this_year()) + EXTRA_COVERAGE;
            *guard = (self.expand(until), until);
        }
        let changes = &guard.0;
        if changes.is_empty() {
            return 0;
        }
        // The change in force: the last whose start, on the earlier of its two clocks, is not
        // after `tt`.
        let local = |c: &Change| Civil(c.utc.0 + c.offset.min(c.prev));
        let idx = changes.partition_point(|c| local(c) <= tt);
        if idx == 0 {
            return 0;
        }
        let idx = idx - 1;
        let mut change = &changes[idx];
        // In the hour that repeats, standard time is chosen.
        if change.offset - change.prev < 0 && idx > 0 && tt < Civil(change.utc.0 + change.prev) {
            let prev = &changes[idx - 1];
            if change.daylight && !prev.daylight {
                change = prev;
            }
        }
        change.offset
    }
}

// ---- Recurrence -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freq {
    Secondly,
    Minutely,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone)]
struct Rule {
    freq: Freq,
    interval: i64,
    count: Option<i64>,
    until: Option<Time>,
    /// (ordinal, weekday 0 = Sunday); ordinal 0 = every.
    by_day: Vec<(i64, i64)>,
    by_month_day: Vec<i64>,
    by_month: Vec<i64>,
    by_year_day: Vec<i64>,
    by_set_pos: Vec<i64>,
    /// Read only to refuse what ical.js refuses; a rule that needs it finds nothing here.
    by_week_no: Vec<i64>,
    by_hour: Vec<i64>,
    by_minute: Vec<i64>,
    by_second: Vec<i64>,
    wkst: i64,
}

static BYDAY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([+-])?(5[0-3]|[1-4][0-9]|[1-9])?(SU|MO|TU|WE|TH|FR|SA)$").expect("regex"));
static DAY_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(SU|MO|TU|WE|TH|FR|SA)$").expect("regex"));

/// `parseInt(s, 10)`: leading space, a sign, then digits; `None` where it gives NaN.
fn js_parse_int(s: &str) -> Option<i64> {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let end = digits.bytes().take_while(u8::is_ascii_digit).count();
    let n: i64 = digits[..end].parse().ok()?;
    Some(if neg { -n } else { n })
}

fn weekday_code(s: &str) -> Option<i64> {
    ["SU", "MO", "TU", "WE", "TH", "FR", "SA"]
        .iter()
        .position(|d| d.eq_ignore_ascii_case(s))
        .map(|i| i as i64)
}

impl Rule {
    /// The rule, or the error ical.js throws for it (which fails the whole expansion in the TS).
    fn parse(v: &str) -> Result<Rule, String> {
        let r = Self::read(v).ok_or_else(|| "invalid recurrence rule".to_string())?;
        let has = |l: &Vec<i64>| !l.is_empty();
        if has(&r.by_year_day) && (has(&r.by_month) || has(&r.by_week_no) || has(&r.by_month_day)) {
            return Err("Invalid BYYEARDAY rule".into());
        }
        if has(&r.by_week_no) && has(&r.by_month_day) {
            return Err("BYWEEKNO does not fit to BYMONTHDAY".into());
        }
        if r.freq == Freq::Monthly && (has(&r.by_year_day) || has(&r.by_week_no)) {
            return Err("For MONTHLY recurrences neither BYYEARDAY nor BYWEEKNO may appear".into());
        }
        if r.freq == Freq::Weekly && (has(&r.by_year_day) || has(&r.by_month_day)) {
            return Err("For WEEKLY recurrences neither BYMONTHDAY nor BYYEARDAY may appear".into());
        }
        if r.freq != Freq::Yearly && has(&r.by_year_day) {
            return Err("BYYEARDAY may only appear in YEARLY rules".into());
        }
        if r.freq == Freq::Monthly && r.by_day.iter().any(|(pos, _)| !(-5..=5).contains(pos)) {
            return Err("Malformed values in BYDAY part".into());
        }
        Ok(r)
    }

    fn read(v: &str) -> Option<Rule> {
        let mut r = Rule {
            freq: Freq::Daily,
            interval: 1,
            count: None,
            until: None,
            by_day: vec![],
            by_month_day: vec![],
            by_month: vec![],
            by_year_day: vec![],
            by_set_pos: vec![],
            by_week_no: vec![],
            by_hour: vec![],
            by_minute: vec![],
            by_second: vec![],
            wkst: 1,
        };
        let mut freq = None;
        // `parseNumericValue`: `parseInt` of each value; a value that is a number outside the
        // range is refused (one that is not a number, like `5x`, is taken as `parseInt` reads it).
        let ints = |s: &str, min: i64, max: i64| {
            s.split(',')
                .map(|x| {
                    let n = js_parse_int(x.strip_prefix('+').unwrap_or(x))?;
                    match x.trim().parse::<f64>() {
                        Ok(f) if f < min as f64 || f > max as f64 => None,
                        _ => Some(n),
                    }
                })
                .collect::<Option<Vec<_>>>()
        };
        for part in v.split(';') {
            // `parts[1]` of `split("=")`: the text up to a second `=`, and none without one.
            let mut kv = part.split('=');
            let k = kv.next().unwrap_or_default();
            let val = kv.next();
            let needs = || val.ok_or(());
            let ok = (|| -> Result<(), ()> {
                match k.to_ascii_uppercase().as_str() {
                    // Case matters here, as in ical.js.
                    "FREQ" => {
                        freq = Some(match needs()? {
                            "SECONDLY" => Freq::Secondly,
                            "MINUTELY" => Freq::Minutely,
                            "HOURLY" => Freq::Hourly,
                            "DAILY" => Freq::Daily,
                            "WEEKLY" => Freq::Weekly,
                            "MONTHLY" => Freq::Monthly,
                            "YEARLY" => Freq::Yearly,
                            _ => return Err(()),
                        })
                    }
                    "INTERVAL" => r.interval = js_parse_int(needs()?).ok_or(())?.max(1),
                    "COUNT" => r.count = Some(js_parse_int(needs()?).ok_or(())?),
                    "UNTIL" => r.until = parse_time(needs()?, None, &HashMap::new(), false),
                    "BYDAY" => {
                        for d in needs()?.split(',') {
                            let c = BYDAY.captures(d).ok_or(())?;
                            let n = c.get(2).map_or(0, |m| m.as_str().parse::<i64>().unwrap_or(0));
                            let n = if c.get(1).is_some_and(|m| m.as_str() == "-") {
                                -n
                            } else {
                                n
                            };
                            r.by_day.push((n, weekday_code(&c[3]).ok_or(())?));
                        }
                    }
                    "BYMONTHDAY" => r.by_month_day = ints(needs()?, -31, 31).ok_or(())?,
                    "BYMONTH" => r.by_month = ints(needs()?, 1, 12).ok_or(())?,
                    "BYYEARDAY" => r.by_year_day = ints(needs()?, -366, 366).ok_or(())?,
                    "BYSETPOS" => r.by_set_pos = ints(needs()?, -366, 366).ok_or(())?,
                    "BYWEEKNO" => r.by_week_no = ints(needs()?, -53, 53).ok_or(())?,
                    "BYHOUR" => r.by_hour = ints(needs()?, 0, 23).ok_or(())?,
                    "BYMINUTE" => r.by_minute = ints(needs()?, 0, 59).ok_or(())?,
                    "BYSECOND" => r.by_second = ints(needs()?, 0, 60).ok_or(())?,
                    "WKST" => {
                        let w = needs()?;
                        if !DAY_NAME.is_match(w) {
                            return Err(());
                        }
                        r.wkst = weekday_code(w).ok_or(())?;
                    }
                    _ => {}
                }
                Ok(())
            })();
            ok.ok()?;
        }
        r.freq = freq?;
        Some(r)
    }
}

/// The occurrences of one rule from `DTSTART` on, in order: each period's candidates (expanded and
/// limited by the BY parts, then BYSETPOS), never before `DTSTART`, until COUNT or UNTIL.
struct RuleIter {
    rule: Rule,
    start: Time,
    period: i64,
    queue: std::collections::VecDeque<Civil>,
    emitted: i64,
    done: bool,
    empty_periods: i64,
    /// ical.js's first occurrence where it differs from the rule's first match (see `monthly_first`),
    /// and the time every later one must be after.
    first: Option<Civil>,
    after: Option<Civil>,
}

impl RuleIter {
    fn new(rule: Rule, start: Time) -> Self {
        RuleIter {
            rule,
            start,
            period: 0,
            queue: Default::default(),
            emitted: 0,
            done: false,
            empty_periods: 0,
            first: None,
            after: None,
        }
        .with_first()
    }

    /// ical.js starts a MONTHLY rule with BYDAY (and no BYMONTHDAY) on the earliest of its weekdays
    /// in DTSTART's month, before BYSETPOS is applied, and gives that first when it is not before
    /// DTSTART. So `BYDAY=MO,WE;BYSETPOS=2` starting on a Monday has that Monday first.
    fn with_first(mut self) -> Self {
        if self.rule.freq != Freq::Monthly || self.rule.by_day.is_empty() || !self.rule.by_month_day.is_empty() {
            return self;
        }
        let (sy, sm, _) = self.start.at.ymd();
        let mut best: Option<i64> = None;
        for &(pos, wd) in &self.rule.by_day {
            if !(-5..=5).contains(&pos) {
                return self;
            }
            let (mut y, mut m) = (sy, sm);
            // A fifth weekday the month lacks is looked for in the months after, unless one was
            // already found in DTSTART's month.
            for _ in 0..24 {
                let first = days_from_civil(y, m, 1);
                let n = days_in_month(y, m);
                let day = Self::nth_days(first, n, if pos == 0 { 1 } else { pos }, wd)
                    .first()
                    .copied();
                if let Some(d) = day {
                    if best.is_none_or(|b| d < b) {
                        best = Some(d);
                    }
                    break;
                }
                if best.is_some_and(|b| civil_from_days(b).1 == sm) {
                    break;
                }
                (y, m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
            }
        }
        if let Some(d) = best {
            let at = Civil(d * 86_400 + self.start.at.secs_of_day());
            if self.start.with(at).unix() >= self.start.unix() {
                self.first = Some(at);
                self.after = Some(at);
            }
        }
        self
    }

    fn times_of_day(&self) -> Vec<i64> {
        let s = self.start.at.secs_of_day();
        let pick = |list: &Vec<i64>, own: i64| if list.is_empty() { vec![own] } else { list.clone() };
        let mut out = Vec::new();
        for h in pick(&self.rule.by_hour, s / 3600) {
            for m in pick(&self.rule.by_minute, s / 60 % 60) {
                for sec in pick(&self.rule.by_second, s % 60) {
                    out.push(h * 3600 + m * 60 + sec);
                }
            }
        }
        out
    }

    /// Weekdays `wd` in days `[first, first + len)`, with an ordinal counted within that range.
    fn nth_days(first: i64, len: i64, ord: i64, wd: i64) -> Vec<i64> {
        let all: Vec<i64> = (first..first + len).filter(|d| (d + 4).rem_euclid(7) == wd).collect();
        match ord {
            0 => all,
            n if n > 0 => all.get((n - 1) as usize).into_iter().copied().collect(),
            n => all
                .len()
                .checked_sub((-n) as usize)
                .and_then(|i| all.get(i))
                .into_iter()
                .copied()
                .collect(),
        }
    }

    fn month_days(y: i64, m: i64, list: &[i64]) -> Vec<i64> {
        let first = days_from_civil(y, m, 1);
        let n = days_in_month(y, m);
        list.iter()
            .filter_map(|&d| {
                let d = if d < 0 { n + d + 1 } else { d };
                (1..=n).contains(&d).then(|| first + d - 1)
            })
            .collect()
    }

    /// The days of one period, before BYSETPOS and the time of day.
    fn period_days(&self, k: i64) -> Vec<i64> {
        let r = &self.rule;
        if !r.by_week_no.is_empty() {
            return vec![];
        }
        let (sy, sm, sd) = self.start.at.ymd();
        let start_day = self.start.at.days();
        let wd = |d: i64| (d + 4).rem_euclid(7);
        let in_month = |d: i64| r.by_month.is_empty() || r.by_month.contains(&civil_from_days(d).1);
        let month_day_ok = |d: i64| {
            if r.by_month_day.is_empty() {
                return true;
            }
            let (y, m, dd) = civil_from_days(d);
            let n = days_in_month(y, m);
            r.by_month_day.iter().any(|&x| x == dd || (x < 0 && n + x + 1 == dd))
        };
        let day_ok = |d: i64| r.by_day.is_empty() || r.by_day.iter().any(|(_, w)| *w == wd(d));
        let mut days: Vec<i64> = match r.freq {
            Freq::Secondly | Freq::Minutely | Freq::Hourly => {
                // Sub-daily rules are not used by invites; treat each period as one day.
                vec![start_day + k]
            }
            Freq::Daily => {
                let d = start_day + k * r.interval;
                [d].into_iter()
                    .filter(|&d| in_month(d) && month_day_ok(d) && day_ok(d))
                    .collect()
            }
            Freq::Weekly => {
                let week_start = start_day - (wd(start_day) - r.wkst).rem_euclid(7) + k * 7 * r.interval;
                let wanted: Vec<i64> = if r.by_day.is_empty() {
                    vec![wd(start_day)]
                } else {
                    r.by_day.iter().map(|(_, w)| *w).collect()
                };
                (week_start..week_start + 7)
                    .filter(|&d| wanted.contains(&wd(d)) && in_month(d))
                    .collect()
            }
            Freq::Monthly => {
                let idx = sy * 12 + (sm - 1) + k * r.interval;
                let (y, m) = (idx.div_euclid(12), idx.rem_euclid(12) + 1);
                if !r.by_month.is_empty() && !r.by_month.contains(&m) {
                    vec![]
                } else {
                    let first = days_from_civil(y, m, 1);
                    let n = days_in_month(y, m);
                    if !r.by_day.is_empty() {
                        let mut v: Vec<i64> = r
                            .by_day
                            .iter()
                            .flat_map(|&(o, w)| Self::nth_days(first, n, o, w))
                            .collect();
                        if !r.by_month_day.is_empty() {
                            v.retain(|&d| month_day_ok(d));
                        }
                        v
                    } else if !r.by_month_day.is_empty() {
                        Self::month_days(y, m, &r.by_month_day)
                    } else if sd <= n {
                        vec![first + sd - 1]
                    } else {
                        vec![]
                    }
                }
            }
            Freq::Yearly => {
                let y = sy + k * r.interval;
                let first = days_from_civil(y, 1, 1);
                let len = if leap(y) { 366 } else { 365 };
                if !r.by_year_day.is_empty() {
                    r.by_year_day
                        .iter()
                        .filter_map(|&n| {
                            let n = if n < 0 { len + n + 1 } else { n };
                            (1..=len).contains(&n).then(|| first + n - 1)
                        })
                        .filter(|&d| day_ok(d))
                        .collect()
                } else if !r.by_month.is_empty() {
                    let mut v = Vec::new();
                    for &m in &r.by_month {
                        if !(1..=12).contains(&m) {
                            continue;
                        }
                        let mf = days_from_civil(y, m, 1);
                        let n = days_in_month(y, m);
                        if !r.by_day.is_empty() {
                            let mut days: Vec<i64> = r
                                .by_day
                                .iter()
                                .flat_map(|&(o, w)| Self::nth_days(mf, n, o, w))
                                .collect();
                            if !r.by_month_day.is_empty() {
                                days.retain(|&d| month_day_ok(d));
                            }
                            v.extend(days);
                        } else if !r.by_month_day.is_empty() {
                            v.extend(Self::month_days(y, m, &r.by_month_day));
                        } else if sd <= n {
                            v.push(mf + sd - 1);
                        }
                    }
                    v
                } else if !r.by_day.is_empty() {
                    let mut v: Vec<i64> = r
                        .by_day
                        .iter()
                        .flat_map(|&(o, w)| Self::nth_days(first, len, o, w))
                        .collect();
                    if !r.by_month_day.is_empty() {
                        v.retain(|&d| month_day_ok(d));
                    }
                    v
                } else if !r.by_month_day.is_empty() {
                    Self::month_days(y, sm, &r.by_month_day)
                } else if sd <= days_in_month(y, sm) {
                    vec![days_from_civil(y, sm, sd)]
                } else {
                    vec![]
                }
            }
        };
        days.sort_unstable();
        days.dedup();
        days
    }

    fn fill(&mut self) {
        while self.queue.is_empty() && !self.done {
            let days = self.period_days(self.period);
            self.period += 1;
            let mut cands: Vec<Civil> = Vec::new();
            let times = self.times_of_day();
            for d in &days {
                for &t in &times {
                    cands.push(Civil(d * 86_400 + t));
                }
            }
            cands.sort_unstable();
            if !self.rule.by_set_pos.is_empty() {
                let n = cands.len() as i64;
                let mut picked: Vec<Civil> = self
                    .rule
                    .by_set_pos
                    .iter()
                    .filter_map(|&p| {
                        let i = if p < 0 { n + p } else { p - 1 };
                        (0..n).contains(&i).then(|| cands[i as usize])
                    })
                    .collect();
                picked.sort_unstable();
                picked.dedup();
                cands = picked;
            }
            let start = self.start.unix();
            cands.retain(|c| self.start.with(*c).unix() >= start);
            if cands.is_empty() {
                self.empty_periods += 1;
                // A rule that can never match (the 30th of February): stop, as ical.js does.
                if self.empty_periods > 2000 {
                    self.done = true;
                }
                continue;
            }
            self.empty_periods = 0;
            self.queue.extend(cands);
        }
    }

    fn next(&mut self) -> Option<Time> {
        if self.done || self.rule.count.is_some_and(|c| self.emitted >= c) {
            self.done = true;
            return None;
        }
        let at = match self.first.take() {
            Some(at) => at,
            None => loop {
                self.fill();
                let at = self.queue.pop_front()?;
                if self.after.is_none_or(|a| at > a) {
                    break at;
                }
            },
        };
        let t = self.start.with(at);
        if let Some(u) = &self.rule.until
            && t.unix() > u.unix()
        {
            self.done = true;
            return None;
        }
        self.emitted += 1;
        Some(t)
    }
}

/// `binsearchInsert`: where `seek` goes in the sorted `list`; at an equal element, its index.
fn binsearch_insert<T>(list: &[T], mut cmp: impl FnMut(&T) -> std::cmp::Ordering) -> usize {
    use std::cmp::Ordering::*;
    if list.is_empty() {
        return 0;
    }
    let (mut low, mut high) = (0i64, list.len() as i64 - 1);
    let (mut mid, mut last) = (0i64, Equal);
    while low <= high {
        mid = low + (high - low) / 2;
        // `cmpfunc(seekVal, list[mid])`: how the sought value compares with the element.
        last = cmp(&list[mid as usize]);
        match last {
            Less => high = mid - 1,
            Greater => low = mid + 1,
            Equal => break,
        }
    }
    (if last == Greater { mid + 1 } else { mid }) as usize
}

/// ical.js's `_compare_special`: a DATE-TIME against a DATE compares the days only.
fn compare_special(a: &Time, b: &Time) -> std::cmp::Ordering {
    if !a.is_date && b.is_date {
        a.at.days().cmp(&b.at.days())
    } else {
        a.unix().cmp(&b.unix())
    }
}

/// `ICAL.RecurExpansion`: the rules' occurrences and the `RDATE`s merged in order, less `EXDATE`s,
/// with its pointers as ical.js keeps them. An error is what ical.js throws.
struct Expansion {
    rules: Vec<(RuleIter, Option<Time>)>,
    rdates: Vec<Time>,
    rdate: usize,
    exdates: Vec<Time>,
    exdate: usize,
}

impl Expansion {
    fn new(event: &Component, start: &Time, zones: &HashMap<String, Arc<Timezone>>) -> Result<Self, String> {
        let mut rules = Vec::new();
        for p in event.all("rrule") {
            let mut it = RuleIter::new(Rule::parse(&p.value)?, start.clone());
            let first = it.next();
            rules.push((it, first));
        }
        let rdates = prop_times(event, "rdate", zones)?;
        // ical.js's "special hack": a first RDATE before DTSTART is where the series starts.
        let rdate = match rdates.first() {
            Some(first) if first.unix() < start.unix() => 0,
            _ => binsearch_insert(&rdates, |r| start.unix().cmp(&r.unix())),
        };
        let exdates = prop_times(event, "exdate", zones)?;
        let exdate = binsearch_insert(&exdates, |x| compare_special(start, x));
        Ok(Expansion {
            rules,
            rdates,
            rdate,
            exdates,
            exdate,
        })
    }

    fn next(&mut self) -> Result<Option<Time>, String> {
        for tries in 0.. {
            if tries > 500 {
                return Err("max tries have occurred, rule may be impossible to fulfill.".into());
            }
            let rule = self
                .rules
                .iter()
                .enumerate()
                .filter_map(|(i, (_, t))| t.as_ref().map(|t| (i, t.unix())))
                .min_by_key(|(_, u)| *u);
            let rdate = self.rdates.get(self.rdate).map(Time::unix);
            // The RDATE first unless a rule's occurrence is earlier; one at the same time as an
            // occurrence comes out twice, as in ical.js.
            let next = match (rule, rdate) {
                (None, None) => return Ok(None),
                (Some((i, ru)), rd) if rd.is_none_or(|rd| rd > ru) => {
                    let (it, slot) = &mut self.rules[i];
                    let t = slot.take();
                    *slot = it.next();
                    t
                }
                _ => {
                    self.rdate += 1;
                    self.rdates.get(self.rdate - 1).cloned()
                }
            };
            let Some(next) = next else { return Ok(None) };
            if let Some(x) = self.exdates.get(self.exdate) {
                match compare_special(&next, x) {
                    std::cmp::Ordering::Greater => self.exdate += 1,
                    std::cmp::Ordering::Equal => {
                        self.exdate += 1;
                        continue;
                    }
                    std::cmp::Ordering::Less => {}
                }
            }
            return Ok(Some(next));
        }
        Ok(None)
    }
}

// ---- Invites --------------------------------------------------------------------------------

fn sequence_of(e: &Component) -> i64 {
    e.first("sequence")
        .and_then(|p| p.value.trim().parse::<f64>().ok())
        .filter(|f| f.is_finite() && *f != 0.0)
        .map_or(0, |f| f as i64)
}

fn recurrence_id(e: &Component, zones: &HashMap<String, Arc<Timezone>>) -> Option<String> {
    prop_time(e, "recurrence-id", zones).map(|t| iso(t.unix_ms()))
}

fn wanted(method: &str) -> bool {
    matches!(method, "REQUEST" | "PUBLISH" | "CANCEL")
}

/// The event ids a file is about, so its sender's later files can be kept together.
pub fn invite_uids(text: &str) -> Vec<String> {
    let Some(c) = parse(text) else { return vec![] };
    if !wanted(&c.method) {
        return vec![];
    }
    let mut seen = HashSet::new();
    c.events
        .iter()
        .map(|e| value(e, "uid"))
        .filter(|u| !u.is_empty() && u.encode_utf16().count() <= 512 && seen.insert(u.clone()))
        .collect()
}

/// What one event's invites, oldest first, add up to between `from` and `to`: the latest request
/// wins, a changed occurrence replaces the regular one, a cancellation removes the event or the one
/// occurrence it names. Replies (METHOD:REPLY) and anything unreadable are skipped. The error is
/// where ical.js throws (a rule it refuses, a PERIOD in RDATE, over 500 occurrences in a row
/// excluded): the TS's `expandInvites` throws then, and its caller gives up on that sync.
pub fn expand_invites(uid: &str, files: &[String], from: i64, to: i64) -> Result<Vec<InviteOccurrence>, String> {
    // Each event keeps the zones of the file it came in.
    type Held = (Component, HashMap<String, Arc<Timezone>>);
    let mut master: Option<Held> = None;
    let mut cancelled = false;
    let mut changed: BTreeMap<String, Held> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut dropped: HashSet<String> = HashSet::new();
    for text in files {
        let Some(cal) = parse(text) else { continue };
        if !wanted(&cal.method) {
            continue;
        }
        for event in &cal.events {
            if value(event, "uid") != uid {
                continue;
            }
            let rid = recurrence_id(event, &cal.zones);
            let gone = cal.method == "CANCEL" || value(event, "status").to_uppercase() == "CANCELLED";
            if let Some(rid) = rid {
                if changed
                    .get(&rid)
                    .is_some_and(|(k, _)| sequence_of(k) > sequence_of(event))
                {
                    continue;
                }
                if gone {
                    dropped.insert(rid.clone());
                    changed.remove(&rid);
                    order.retain(|r| r != &rid);
                } else {
                    dropped.remove(&rid);
                    if !changed.contains_key(&rid) {
                        order.push(rid.clone());
                    }
                    changed.insert(rid, (event.clone(), cal.zones.clone()));
                }
            } else if master.is_none()
                || master
                    .as_ref()
                    .is_some_and(|(m, _)| sequence_of(event) >= sequence_of(m))
                || gone
            {
                if gone
                    && master
                        .as_ref()
                        .is_some_and(|(m, _)| sequence_of(event) < sequence_of(m))
                {
                    continue;
                }
                cancelled = gone;
                if !gone {
                    // A new time for the whole series makes the old one-off changes meaningless.
                    if master
                        .as_ref()
                        .is_some_and(|(m, _)| sequence_of(event) > sequence_of(m))
                    {
                        changed.clear();
                        order.clear();
                        dropped.clear();
                    }
                    master = Some((event.clone(), cal.zones.clone()));
                }
            }
        }
    }
    if cancelled {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    let mut add = |key: String, event: &Component, start: &Time, end: &Time| {
        // An all-day event has no time to join at.
        if start.is_date {
            return;
        }
        let (s, e) = (start.unix_ms(), end.unix_ms());
        if e <= s || e <= from || s >= to {
            return;
        }
        let x = value(event, "x-google-conference");
        let (loc, desc) = (value(event, "location"), value(event, "description"));
        let Some(url) = meet_link(&[Some(&x), Some(&loc), Some(&desc)]) else {
            return;
        };
        let title: String = value(event, "summary").split_whitespace().collect::<Vec<_>>().join(" ");
        let title: String = title
            .chars()
            .scan(0, |n, c| {
                *n += c.len_utf16();
                (*n <= 200).then_some(c)
            })
            .collect();
        out.push(InviteOccurrence {
            key,
            uid: uid.to_string(),
            start: s,
            end: e,
            url,
            title,
        });
    };
    let bounds = |c: &Component, zones: &HashMap<String, Arc<Timezone>>| -> Option<(Time, Time)> {
        let start = prop_time(c, "dtstart", zones)?;
        let end = match prop_time(c, "dtend", zones) {
            Some(e) => e,
            None => {
                let mut e = start.clone();
                match c.first("duration").and_then(|p| parse_duration(&p.value)) {
                    Some(d) => e.at = Civil(e.at.0 + d),
                    None if e.is_date => e.at = Civil(e.at.0 + 86_400),
                    None => {}
                }
                e
            }
        };
        Some((start, end))
    };
    if let Some((m, zones)) = &master {
        let Some((start, end)) = bounds(m, zones) else {
            return Ok(vec![]);
        };
        let recurring = m.first("rrule").is_some() || m.first("rdate").is_some();
        if !recurring {
            add(format!("{uid}|"), m, &start, &end);
        } else {
            // The length on the wall clock, kept for every occurrence.
            let length = end.at.0 - start.at.0;
            let mut exp = Expansion::new(m, &start, zones)?;
            let mut i = 0;
            while let Some(next) = exp.next()? {
                if i >= MAX_OCCURRENCES || next.unix_ms() >= to {
                    break;
                }
                i += 1;
                let rid = iso(next.unix_ms());
                if dropped.contains(&rid) || changed.contains_key(&rid) {
                    continue;
                }
                let end = next.with(Civil(next.at.0 + length));
                add(format!("{uid}|{rid}"), m, &next, &end);
            }
        }
    }
    // Changed occurrences, and one-off changes that arrived without the series they belong to.
    for rid in &order {
        if let Some((c, zones)) = changed.get(rid)
            && let Some((start, end)) = bounds(c, zones)
        {
            add(format!("{uid}|{rid}"), c, &start, &end);
        }
    }
    out.sort_by_key(|o| o.start);
    Ok(out)
}

#[cfg(test)]
pub(super) mod tests;
