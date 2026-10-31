//! Where scheduled meetings come from (`meeting-sources.ts`, docs/plans/meetjoin.md): invite files
//! in the agent's AgentMail inbox, and Meet events on the connected Google Calendar. Both go out
//! through the org firewall with this box's placeholders, like the agent's own tools: the firewall
//! puts the real key in, and for AgentMail it shows only mail from allowed senders.

use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use super::ics::{MAX_ICS_BYTES, meet_link};
use super::js::len16;
use crate::boxside::shell::encode_uri_component;
use crate::phone::history::parse_iso;
use crate::platform::time::iso_ms;

pub const AGENTMAIL_API: &str = "https://api.agentmail.to/v0";
pub const CALENDAR_API: &str = "https://www.googleapis.com/calendar/v3";
const FIRST_LOOK_BACK_MS: i64 = 14 * 24 * 3_600_000;
const MAX_PAGES: usize = 5;
const WAIT: Duration = Duration::from_secs(20);

/// JavaScript's `\s`, as a regex class body.
const SPACE: &str = r"\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}";

/// `envFile`: the `KEY=value` lines of an env file this agent wrote itself; quotes around a value
/// are dropped.
pub fn env_file(path: &Path) -> std::collections::HashMap<String, String> {
    static LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Z0-9_]+)=(.*)$").expect("regex"));
    let mut out = std::collections::HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.split('\n') {
        if let Some(m) = LINE.captures(super::js::js_trim(line)) {
            let v = &m[2];
            let unquoted = ['"', '\'']
                .iter()
                .find(|q| v.len() >= 2 && v.starts_with(**q) && v.ends_with(**q))
                .map_or(v, |_| &v[1..v.len() - 1]);
            out.insert(m[1].to_string(), unquoted.to_string());
        }
    }
    out
}

/// `addressOf`: the address in `Name <a@b>` or a bare `a@b`, in lower case.
pub fn address_of(value: Option<&Value>) -> Option<String> {
    static BRACKETS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"<([^<>{SPACE}]+@[^<>{SPACE}]+)>[{SPACE}]*$")).expect("regex"));
    static BARE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"^[{SPACE}]*([^<>{SPACE}]+@[^<>{SPACE}]+)[{SPACE}]*$")).expect("regex"));
    let v = value?.as_str()?;
    let m = BRACKETS.captures(v).or_else(|| BARE.captures(v))?;
    Some(m[1].to_lowercase())
}

/// One invite file from the mailbox: `{id: "<message>:<attachment>", from, ics}`.
#[derive(Debug, Clone, PartialEq)]
pub struct InviteMail {
    pub id: String,
    pub from: String,
    pub ics: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MailBatch {
    pub mails: Vec<InviteMail>,
    pub cursor: String,
    /// A file could not be fetched this time: the same mail is looked at again.
    pub incomplete: bool,
}

/// One Meet event on the calendar.
#[derive(Debug, Clone, PartialEq)]
pub struct CalendarEvent {
    pub id: String,
    pub start: i64,
    pub end: i64,
    pub url: String,
    pub title: String,
    pub organizer: String,
}

/// The HTTP side of both readers; tests point it at a local server.
#[derive(Clone)]
pub struct Http {
    /// The agent's shared client (`app.http`): its no-redirect side, which trusts the firewall's
    /// CA once the bootstrap installed it. A client built at start-up on a new box had no CA and
    /// every call through the firewall failed TLS.
    pub client: cc_client::HttpClient,
    pub agentmail: String,
    pub calendar: String,
    /// Where a download link must point (`https://` on a box).
    pub downloads: String,
}

impl Http {
    /// No proxy (Node's `fetch` reads none) and no redirects (`redirect: "error"`).
    pub fn new(client: cc_client::HttpClient) -> Self {
        Self {
            client,
            agentmail: AGENTMAIL_API.into(),
            calendar: CALENDAR_API.into(),
            downloads: "https://".into(),
        }
    }

    /// `json()`: the answer, or "<host> answered <status>". Never the URL, which a signed link
    /// carries in full.
    async fn json(&self, url: &str, token: Option<&str>) -> Result<Value, String> {
        let mut req = self.client.get_no_redirect().get(url).timeout(WAIT);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let res = req.send().await.map_err(|e| e.without_url().to_string())?;
        if !res.status().is_success() {
            let host = url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_default();
            return Err(format!("{host} answered {}", res.status().as_u16()));
        }
        res.json::<Value>().await.map_err(|e| e.without_url().to_string())
    }

    /// The body as text; `None` when it is larger than an invite can be. Read up to that size only.
    async fn text(&self, url: &str) -> Result<Option<String>, String> {
        let mut res = self
            .client
            .get_no_redirect()
            .get(url)
            .timeout(WAIT)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !res.status().is_success() {
            return Err(format!("invite download answered {}", res.status().as_u16()));
        }
        // A UTF-16 unit takes at most 3 bytes of UTF-8: more than that cannot be an invite.
        let cap = 3 * MAX_ICS_BYTES;
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|e| e.without_url().to_string())? {
            body.extend_from_slice(&chunk);
            if body.len() > cap {
                return Ok(None);
            }
        }
        Ok(Some(String::from_utf8_lossy(&body).into_owned()))
    }
}

fn query(pairs: &[(&str, String)]) -> String {
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        q.append_pair(k, v);
    }
    q.finish()
}

fn is_invite(a: &Value) -> bool {
    static TYPE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)^(?:text/calendar|application/ics)(?-u:\b)").expect("regex"));
    static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.ics$").expect("regex"));
    let text = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or_default();
    a.get("attachment_id").is_some_and(Value::is_string)
        && a.get("size").and_then(Value::as_f64).unwrap_or(0.0) <= MAX_ICS_BYTES as f64
        && (TYPE.is_match(text("content_type")) || NAME.is_match(text("filename")))
}

/// `inviteMailReader`: the invite files in mail received since the cursor (a timestamp), oldest
/// first. `None`: no mailbox on this agent.
pub async fn read_invite_mail(
    http: &Http,
    mailbox: Option<(String, String)>,
    cursor: Option<&str>,
    now: i64,
) -> Result<Option<MailBatch>, String> {
    let Some((inbox, token)) = mailbox else { return Ok(None) };
    let base = format!("{}/inboxes/{}/messages", http.agentmail, encode_uri_component(&inbox));
    let after = cursor.map_or_else(|| iso_ms(now - FIRST_LOOK_BACK_MS), String::from);
    let mut mails = Vec::new();
    let mut latest = after.clone();
    let mut incomplete = false;
    let mut page: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut pairs = vec![
            ("limit", "50".to_string()),
            ("ascending", "true".into()),
            ("after", after.clone()),
        ];
        if let Some(p) = &page {
            pairs.push(("page_token", p.clone()));
        }
        let list = http.json(&format!("{base}?{}", query(&pairs)), Some(&token)).await?;
        for message in list.get("messages").and_then(Value::as_array).into_iter().flatten() {
            if let Some(ts) = message.get("timestamp").and_then(Value::as_str)
                && parse_iso(ts).unwrap_or(f64::NAN) > parse_iso(&latest).unwrap_or(f64::NAN)
            {
                latest = ts.to_string();
            }
            let from = address_of(message.get("from"));
            let labels: Vec<&str> = message
                .get("labels")
                .and_then(Value::as_array)
                .map(|l| l.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            // Mail the agent sent itself, and mail the firewall marked as not allowed, schedules nothing.
            let (Some(id), Some(from)) = (message.get("message_id").and_then(Value::as_str), from) else {
                continue;
            };
            if from == inbox.to_lowercase() || labels.contains(&"sent") || labels.contains(&"blocked") {
                continue;
            }
            let invites: Vec<&Value> = message
                .get("attachments")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|a| is_invite(a))
                .take(3)
                .collect();
            for attachment in invites {
                let aid = attachment["attachment_id"].as_str().unwrap_or_default();
                let where_ = format!(
                    "{base}/{}/attachments/{}",
                    encode_uri_component(id),
                    encode_uri_component(aid)
                );
                // One file that cannot be fetched must not stop the others from being read.
                let fetched: Result<Option<String>, String> = async {
                    let answer = http.json(&where_, Some(&token)).await?;
                    let Some(link) = answer
                        .get("download_url")
                        .and_then(Value::as_str)
                        .filter(|u| u.starts_with(&http.downloads))
                    else {
                        return Ok(None);
                    };
                    http.text(link).await
                }
                .await;
                match fetched {
                    Ok(Some(ics)) if len16(&ics) <= MAX_ICS_BYTES => mails.push(InviteMail {
                        id: format!("{id}:{aid}"),
                        from: from.clone(),
                        ics,
                    }),
                    Ok(_) => {}
                    Err(_) => incomplete = true,
                }
            }
        }
        page = list
            .get("next_page_token")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .map(String::from);
        if page.is_none() {
            break;
        }
    }
    Ok(Some(MailBatch {
        mails,
        cursor: latest,
        incomplete,
    }))
}

const EVENT_FIELDS: &str = "nextPageToken,items(id,status,summary,hangoutLink,location,start/dateTime,end/dateTime,organizer(email,self),attendees(email,self,responseStatus),conferenceData/entryPoints/uri)";

/// `calendarReader`: events with a Meet link on the connected account's own calendar. `invited`:
/// only those that invite the agent; `all`: every one the account has not declined. `None`: no
/// calendar on this agent. `account` is `(token, account address)`.
pub async fn read_calendar(
    http: &Http,
    account: Option<(String, Option<String>)>,
    agent_address: Option<String>,
    from: i64,
    to: i64,
    mode: &str,
) -> Result<Option<Vec<CalendarEvent>>, String> {
    static SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!("[{SPACE}]+")).expect("regex"));
    let Some((token, own_account)) = account else {
        return Ok(None);
    };
    let own = agent_address.map(|a| a.to_lowercase());
    let mut out = Vec::new();
    let mut page: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut pairs = vec![
            ("singleEvents", "true".to_string()),
            ("orderBy", "startTime".into()),
            ("maxResults", "250".into()),
            ("fields", EVENT_FIELDS.into()),
            ("timeMin", iso_ms(from)),
            ("timeMax", iso_ms(to)),
        ];
        if let Some(p) = &page {
            pairs.push(("pageToken", p.clone()));
        }
        let url = format!("{}/calendars/primary/events?{}", http.calendar, query(&pairs));
        let list = http.json(&url, Some(&token)).await?;
        for event in list.get("items").and_then(Value::as_array).into_iter().flatten() {
            let time = |k: &str| {
                event
                    .pointer(&format!("/{k}/dateTime"))
                    .and_then(Value::as_str)
                    .and_then(parse_iso)
            };
            let (Some(id), Some(start), Some(end)) =
                (event.get("id").and_then(Value::as_str), time("start"), time("end"))
            else {
                continue;
            };
            // Cancelled, or declined by this account: nothing to join.
            if event.get("status") == Some(&Value::from("cancelled")) {
                continue;
            }
            let guests: Vec<&Value> = event
                .get("attendees")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .collect();
            let is_self = |g: &&Value| g.get("self") == Some(&Value::Bool(true));
            if guests
                .iter()
                .any(|g| is_self(g) && g.get("responseStatus") == Some(&Value::from("declined")))
            {
                continue;
            }
            let mut texts: Vec<Option<&str>> = vec![event.get("hangoutLink").and_then(Value::as_str)];
            for p in event
                .pointer("/conferenceData/entryPoints")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                texts.push(p.get("uri").and_then(Value::as_str));
            }
            texts.push(event.get("location").and_then(Value::as_str));
            let Some(url) = meet_link(&texts) else { continue };
            let organizer_self = event.pointer("/organizer/self") == Some(&Value::Bool(true));
            let invited = (guests.iter().any(is_self) && !organizer_self)
                || own.as_ref().is_some_and(|own| {
                    guests.iter().any(|g| {
                        g.get("email")
                            .and_then(Value::as_str)
                            .is_some_and(|e| e.to_lowercase() == *own)
                    })
                });
            if mode == "invited" && !invited {
                continue;
            }
            let email = event
                .pointer("/organizer/email")
                .and_then(Value::as_str)
                .map(str::to_lowercase);
            let organizer = if organizer_self {
                own_account.as_ref().map(|a| a.to_lowercase()).or(email)
            } else {
                email
            };
            let Some(organizer) = organizer.filter(|o| !o.is_empty()) else {
                continue;
            };
            let title = event.get("summary").and_then(Value::as_str).unwrap_or_default();
            out.push(CalendarEvent {
                id: id.to_string(),
                start: start as i64,
                end: end as i64,
                url,
                title: super::js::js_trim(&SPACES.replace_all(title, " ")).to_string(),
                organizer,
            });
        }
        page = list
            .get("nextPageToken")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .map(String::from);
        if page.is_none() {
            break;
        }
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests;
