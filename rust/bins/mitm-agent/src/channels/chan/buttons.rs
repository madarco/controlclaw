//! Approve with a button (`code-buttons.ts`, docs/plans/channel-approval-buttons.md), Telegram only.
//!
//! The firewall sends the code message itself with the bot token it holds, with three number
//! buttons and Cancel; the console's code dialog shows one two-digit number. The proxy strips taps
//! out of the agent's `getUpdates` answers and posts them here over loopback (8793). A tap counts
//! only on the message this firewall sent, in that person's own chat, from that person, while they
//! are still a code recipient and the change is open. The right number releases the change's own
//! code on the heartbeat; it applies nothing by itself. A wrong number costs a try and turns the
//! buttons off.

// `offer` and `offer_decision` are called by the consent codes (W3's C2, through its `CodeButtons`
// contract) and the content rules' holds (H4); until those land only the taps and the beat run.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use indexmap::IndexMap;
use rand::Rng;
use regex::Regex;
use serde_json::{Value, json};

use cc_http::BoxFuture;

pub const TAP_PREFIX: &str = "cc1:";
const TELEGRAM_API: &str = "https://api.telegram.org";
const TELEGRAM_TIMEOUT: Duration = Duration::from_secs(10);

fn nonce_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]{22}$").expect("regex"))
}

fn choice_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\d{2}|x|ok)$").expect("regex"))
}

/// A Telegram connection a code can go out on with buttons.
#[derive(Debug, Clone, PartialEq)]
pub struct TelegramButtonsRoute {
    pub connection_id: String,
    pub bot_token: String,
}

/// What the consent module that owns a change answers when a button decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapVerdict {
    /// The right number, nothing applied yet.
    Ok,
    /// A try was counted.
    Wrong,
    /// That was the last try and the change is gone.
    Spent,
    /// Nothing is waiting.
    Gone,
}

pub trait TapOwner: Send + Sync {
    fn tap(&self, correct: bool) -> TapVerdict;
    /// Cancel pressed: drop the change.
    fn cancel(&self);
}

pub type Render = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

pub struct OfferInput {
    pub change_id: String,
    pub route: TelegramButtonsRoute,
    /// The approved person's Telegram id, which is also their private chat with the bot.
    pub sender_id: String,
    pub text: String,
    /// The same message with another last line of part one: what every later edit says.
    pub render: Render,
    /// The change's code, released on the heartbeat once the right number is tapped.
    pub code: String,
    pub expires_at: i64,
    pub owner: Arc<dyn TapOwner>,
}

/// What the message says once a decision is made: Send, Don't send, or nobody answered.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionLines {
    pub approved: String,
    pub cancelled: String,
    pub expired: String,
}

pub struct DecisionInput {
    pub change_id: String,
    pub route: TelegramButtonsRoute,
    pub sender_id: String,
    pub text: String,
    pub render: Render,
    pub expires_at: i64,
    pub owner: Arc<dyn TapOwner>,
    pub lines: DecisionLines,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapState {
    Open,
    Approved,
    Refused,
    Cancelled,
}

impl TapState {
    fn as_str(self) -> &'static str {
        match self {
            TapState::Open => "open",
            TapState::Approved => "approved",
            TapState::Refused => "refused",
            TapState::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone)]
struct Offer {
    change_id: String,
    number: String,
    connection_id: String,
    bot_token: String,
    chat_id: String,
    user_id: String,
    message_id: i64,
    render: Render,
    code: String,
    expires_at: i64,
    state: TapState,
    owner: Arc<dyn TapOwner>,
    lines: Option<DecisionLines>,
}

/// The Bot API calls, so tests can stand in for Telegram. `Ok(result)` only when Telegram said ok.
pub trait TelegramApi: Send + Sync {
    fn call(&self, token: &str, method: &str, body: Value) -> BoxFuture<Result<Value, String>>;
}

pub struct LiveTelegram(pub reqwest::Client);

impl TelegramApi for LiveTelegram {
    fn call(&self, token: &str, method: &str, body: Value) -> BoxFuture<Result<Value, String>> {
        let req = self
            .0
            .post(format!("{TELEGRAM_API}/bot{token}/{method}"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .timeout(TELEGRAM_TIMEOUT);
        let method = method.to_string();
        Box::pin(async move {
            // Never the URL in an error: it has the token in it.
            let res = req
                .send()
                .await
                .map_err(|_| format!("Telegram {method} failed (no answer)"))?;
            let status = res.status().as_u16();
            let j: Option<Value> = res.json().await.ok();
            match j {
                Some(j) if j.get("ok") == Some(&Value::Bool(true)) => {
                    Ok(j.get("result").cloned().unwrap_or(Value::Null))
                }
                j => {
                    let desc = j
                        .as_ref()
                        .and_then(|j| j.get("description"))
                        .and_then(Value::as_str)
                        .map(|d| format!(": {}", d.chars().take(120).collect::<String>()))
                        .unwrap_or_default();
                    Err(format!("Telegram {method} failed (HTTP {status}{desc})"))
                }
            }
        })
    }
}

/// The order the three numbers are shown in (a test hook).
pub type Shuffle = Arc<dyn Fn(Vec<String>) -> Vec<String> + Send + Sync>;

pub type Approved = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;
pub type TokenFor = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub struct CodeButtonsOptions {
    /// Whether that person is still on "Who gets confirmation codes" for that connection.
    pub approved: Approved,
    /// The bot token for a bot id, to answer a tap on a message this firewall no longer tracks.
    pub token_for: Option<TokenFor>,
    /// A tap changed what the heartbeat reports: beat soon.
    pub changed: Option<Arc<dyn Fn() + Send + Sync>>,
    pub telegram: Arc<dyn TelegramApi>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// Test hooks: `[right, decoy, decoy]`, and the order the three are shown in.
    pub make_numbers: Option<Arc<dyn Fn() -> [String; 3] + Send + Sync>>,
    pub shuffle: Option<Shuffle>,
}

fn two_digits() -> String {
    rand::thread_rng().gen_range(10..100).to_string()
}

fn make_numbers() -> [String; 3] {
    let right = two_digits();
    let mut decoys: Vec<String> = Vec::new();
    while decoys.len() < 2 {
        let n = two_digits();
        if n != right && !decoys.contains(&n) {
            decoys.push(n);
        }
    }
    [right, decoys[0].clone(), decoys[1].clone()]
}

fn shuffle(mut items: Vec<String>) -> Vec<String> {
    let mut rng = rand::thread_rng();
    for i in (1..items.len()).rev() {
        let j = rng.gen_range(0..=i);
        items.swap(i, j);
    }
    items
}

fn new_nonce() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

/// `String(v)` for a Telegram id that is a number, or a string of digits.
fn id_string(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s)
            if !s.is_empty() && s.trim_start_matches('-').bytes().all(|b| b.is_ascii_digit()) && s != "-" =>
        {
            Some(s.clone())
        }
        _ => None,
    }
}

fn bot_id_of(token: &str) -> &str {
    token.split(':').next().unwrap_or_default()
}

/// One offer as the heartbeat reports it. `code` only once the right number was tapped.
#[derive(Debug, Clone, PartialEq)]
pub struct TapView {
    pub change_id: String,
    pub number: String,
    pub state: TapState,
    pub expires_at: String,
    pub code: Option<String>,
}

impl TapView {
    pub fn to_json(&self) -> Value {
        let mut v = json!({"changeId": self.change_id, "number": self.number, "state": self.state.as_str(), "expiresAt": self.expires_at});
        if let Some(c) = &self.code {
            v["code"] = json!(c);
        }
        v
    }
}

pub struct CodeButtons {
    opts: CodeButtonsOptions,
    offers: Mutex<IndexMap<String, Offer>>,
}

impl CodeButtons {
    pub fn new(opts: CodeButtonsOptions) -> Self {
        Self {
            opts,
            offers: Mutex::new(IndexMap::new()),
        }
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    fn offers(&self) -> std::sync::MutexGuard<'_, IndexMap<String, Offer>> {
        self.offers.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn changed(&self) {
        if let Some(c) = &self.opts.changed {
            c();
        }
    }

    /// Send the code with buttons. The offer's nonce, or `None` when Telegram did not take the
    /// message, and the caller sends the plain code through the agent as before.
    pub async fn offer(&self, input: OfferInput) -> Option<String> {
        let nonce = new_nonce();
        let [right, a, b] = self.opts.make_numbers.as_ref().map_or_else(make_numbers, |f| f());
        let three = vec![right.clone(), a, b];
        let order = match &self.opts.shuffle {
            Some(f) => f(three),
            None => shuffle(three),
        };
        let row: Vec<Value> = order
            .iter()
            .map(|n| json!({"text": n, "callback_data": format!("{TAP_PREFIX}{nonce}:{n}")}))
            .collect();
        let body = json!({
            "chat_id": input.sender_id,
            "text": input.text,
            "reply_markup": {"inline_keyboard": [row, [{"text": "Cancel", "callback_data": format!("{TAP_PREFIX}{nonce}:x")}]]},
        });
        let message_id = match self.send(&input.route.bot_token, body).await {
            Ok(id) => id,
            Err(e) => {
                tracing::info!("[buttons] could not send the code with buttons: {e}");
                return None;
            }
        };
        self.offers().insert(
            nonce.clone(),
            Offer {
                change_id: input.change_id,
                number: right,
                connection_id: input.route.connection_id,
                bot_token: input.route.bot_token,
                chat_id: input.sender_id.clone(),
                user_id: input.sender_id,
                message_id,
                render: input.render,
                code: input.code,
                expires_at: input.expires_at,
                state: TapState::Open,
                owner: input.owner,
                lines: None,
            },
        );
        Some(nonce)
    }

    /// Ask a question the firewall decides itself, with Send and Don't send.
    pub async fn offer_decision(&self, input: DecisionInput) -> Option<String> {
        let nonce = new_nonce();
        let body = json!({
            "chat_id": input.sender_id,
            "text": input.text,
            "reply_markup": {"inline_keyboard": [[
                {"text": "Send", "callback_data": format!("{TAP_PREFIX}{nonce}:ok")},
                {"text": "Don't send", "callback_data": format!("{TAP_PREFIX}{nonce}:x")},
            ]]},
        });
        let message_id = match self.send(&input.route.bot_token, body).await {
            Ok(id) => id,
            Err(e) => {
                tracing::info!("[buttons] could not send the question: {e}");
                return None;
            }
        };
        self.offers().insert(
            nonce.clone(),
            Offer {
                change_id: input.change_id,
                number: String::new(),
                connection_id: input.route.connection_id,
                bot_token: input.route.bot_token,
                chat_id: input.sender_id.clone(),
                user_id: input.sender_id,
                message_id,
                render: input.render,
                code: String::new(),
                expires_at: input.expires_at,
                state: TapState::Open,
                owner: input.owner,
                lines: Some(input.lines),
            },
        );
        Some(nonce)
    }

    async fn send(&self, token: &str, body: Value) -> Result<i64, String> {
        let sent = self.opts.telegram.call(token, "sendMessage", body).await?;
        sent.get("message_id")
            .and_then(Value::as_i64)
            .ok_or_else(|| "no message id in the answer".to_string())
    }

    /// Whether an offer still waits for a tap.
    pub fn is_open(&self, nonce: &str) -> bool {
        self.offers().get(nonce).is_some_and(|o| o.state == TapState::Open)
    }

    /// The change is over on the consent side: take the buttons off and say so. `how` is
    /// `confirmed`, `closed` or `expired`; `line` replaces the words.
    pub async fn settle(&self, nonce: Option<&str>, how: &str, line: Option<&str>) {
        let offer = {
            let mut offers = self.offers();
            let Some(n) = nonce else { return };
            match offers.get(n) {
                None => return,
                // Cancelled from Telegram: the offer stays until it expires so the heartbeat can
                // tell the console to close its dialog.
                Some(o) if o.state == TapState::Cancelled && o.lines.is_none() => return,
                Some(_) => offers.shift_remove(n),
            }
        };
        let Some(offer) = offer else { return };
        let words = line.map(str::to_string).unwrap_or_else(|| match how {
            "confirmed" => "Confirmed.".into(),
            "expired" => offer
                .lines
                .as_ref()
                .map(|l| l.expired.clone())
                .unwrap_or_else(|| "This request expired. Nothing was changed.".into()),
            _ => "This request is closed.".into(),
        });
        self.edit(&offer, &words).await;
    }

    /// Taps the proxy took out of a `getUpdates` answer for bot `bot_id`, each decided on its own.
    pub async fn taps(&self, bot_id: Option<&str>, queries: &[Value]) {
        for q in queries {
            self.tap(bot_id, q).await;
        }
    }

    async fn tap(&self, bot_id: Option<&str>, raw: &Value) {
        let Some(q) = raw.as_object() else { return };
        let Some(query_id) = q.get("id").and_then(Value::as_str) else {
            return;
        };
        let data = q.get("data").and_then(Value::as_str).unwrap_or_default();
        let Some(rest) = data.strip_prefix(TAP_PREFIX) else {
            return;
        };
        let mut parts = rest.split(':');
        let (nonce, choice) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
        let found = (nonce_re().is_match(nonce) && choice_re().is_match(choice))
            .then(|| self.offers().get(nonce).cloned())
            .flatten();
        let offer = match found {
            Some(o) if bot_id.is_none_or(|b| bot_id_of(&o.bot_token) == b) => o,
            _ => {
                let token = bot_id.and_then(|b| self.opts.token_for.as_ref().and_then(|f| f(b)));
                if let Some(t) = token {
                    self.answer(&t, query_id, "This request is closed.").await;
                }
                return;
            }
        };
        let msg = q.get("message");
        let from = id_string(q.get("from").and_then(|f| f.get("id")));
        let chat = id_string(msg.and_then(|m| m.get("chat")).and_then(|c| c.get("id")));
        let same_message = msg.and_then(|m| m.get("message_id")).and_then(Value::as_i64) == Some(offer.message_id);
        let private = msg
            .and_then(|m| m.get("chat"))
            .and_then(|c| c.get("type"))
            .and_then(Value::as_str)
            == Some("private");
        if from.as_deref() != Some(offer.user_id.as_str())
            || chat.as_deref() != Some(offer.chat_id.as_str())
            || !same_message
            || !private
        {
            self.answer(&offer.bot_token, query_id, "This button is not for you.")
                .await;
            return;
        }
        if !(self.opts.approved)(&offer.connection_id, &offer.user_id) {
            self.answer(&offer.bot_token, query_id, "You are no longer set to confirm changes.")
                .await;
            return;
        }
        if self.now() > offer.expires_at {
            self.offers().shift_remove(nonce);
            self.answer(&offer.bot_token, query_id, "This request expired.").await;
            let words = offer
                .lines
                .as_ref()
                .map(|l| l.expired.clone())
                .unwrap_or_else(|| "This request expired. Nothing was changed.".into());
            self.edit(&offer, &words).await;
            if offer.lines.is_some() && offer.state == TapState::Open {
                offer.owner.cancel();
            }
            self.changed();
            return;
        }
        // The state is read and moved under the lock, so two taps at once decide once.
        let state = self.offers().get(nonce).map(|o| o.state);
        match state {
            Some(TapState::Open) => {}
            Some(s) => {
                let words = if s == TapState::Approved {
                    "Already approved."
                } else {
                    "This request is closed."
                };
                self.answer(&offer.bot_token, query_id, words).await;
                return;
            }
            None => {
                self.answer(&offer.bot_token, query_id, "This request is closed.").await;
                return;
            }
        }
        if offer.lines.is_some() {
            self.decide(&offer, nonce, query_id, choice).await;
            return;
        }
        if choice == "ok" {
            self.answer(&offer.bot_token, query_id, "This request is closed.").await;
            return;
        }
        if choice == "x" {
            if !self.take(nonce, TapState::Cancelled) {
                self.answer(&offer.bot_token, query_id, "This request is closed.").await;
                return;
            }
            offer.owner.cancel();
            tracing::info!("[buttons] change {} cancelled from Telegram", offer.change_id);
            self.answer(&offer.bot_token, query_id, "Cancelled.").await;
            self.edit(&offer, "Cancelled. Nothing was changed.").await;
            self.changed();
            return;
        }
        // Claim the tap before asking the owner, so a second tap waits for nothing and counts once.
        if !self.take(nonce, TapState::Refused) {
            self.answer(&offer.bot_token, query_id, "This request is closed.").await;
            return;
        }
        let verdict = offer.owner.tap(choice == offer.number);
        match verdict {
            TapVerdict::Gone => {
                self.offers().shift_remove(nonce);
                self.answer(&offer.bot_token, query_id, "This request is closed.").await;
                self.edit(&offer, "This request is closed.").await;
                return;
            }
            TapVerdict::Spent => {
                self.set_state(nonce, TapState::Cancelled);
                tracing::info!("[buttons] change {}: a wrong number on the last try", offer.change_id);
                self.answer(
                    &offer.bot_token,
                    query_id,
                    "That is not the number in your console. No tries left.",
                )
                .await;
                self.edit(
                    &offer,
                    "That was not the number in your console, and it was the last try. Nothing was changed.",
                )
                .await;
            }
            TapVerdict::Ok => {
                self.set_state(nonce, TapState::Approved);
                tracing::info!("[buttons] change {} approved from Telegram", offer.change_id);
                self.answer(&offer.bot_token, query_id, "Approved.").await;
                self.edit(&offer, "Approved. Your console is applying the change.")
                    .await;
            }
            TapVerdict::Wrong => {
                tracing::info!("[buttons] change {}: a wrong number was tapped", offer.change_id);
                self.answer(&offer.bot_token, query_id, "That is not the number in your console.")
                    .await;
                self.edit(
                    &offer,
                    "That was not the number in your console, so the buttons are off. To confirm, type the code above in the console.",
                )
                .await;
            }
        }
        self.changed();
    }

    /// Move an open offer to `to`; false when it was no longer open (another tap got there first).
    fn take(&self, nonce: &str, to: TapState) -> bool {
        let mut offers = self.offers();
        match offers.get_mut(nonce) {
            Some(o) if o.state == TapState::Open => {
                o.state = to;
                true
            }
            _ => false,
        }
    }

    fn set_state(&self, nonce: &str, to: TapState) {
        if let Some(o) = self.offers().get_mut(nonce) {
            o.state = to;
        }
    }

    /// Send or Don't send on a decision offer. A number on one is not a decision.
    async fn decide(&self, offer: &Offer, nonce: &str, query_id: &str, choice: &str) {
        let lines = offer.lines.clone().unwrap_or(DecisionLines {
            approved: String::new(),
            cancelled: String::new(),
            expired: String::new(),
        });
        if choice == "ok" {
            if !self.take(nonce, TapState::Approved) {
                self.answer(&offer.bot_token, query_id, "This request is closed.").await;
                return;
            }
            tracing::info!("[buttons] {}: Send tapped", offer.change_id);
            self.answer(&offer.bot_token, query_id, "Sending.").await;
            self.edit(offer, &lines.approved).await;
            // The owner sends it and settles the message with what happened.
            offer.owner.tap(true);
        } else if choice == "x" {
            if !self.take(nonce, TapState::Cancelled) {
                self.answer(&offer.bot_token, query_id, "This request is closed.").await;
                return;
            }
            self.offers().shift_remove(nonce);
            tracing::info!("[buttons] {}: Don't send tapped", offer.change_id);
            self.answer(&offer.bot_token, query_id, "Not sent.").await;
            self.edit(offer, &lines.cancelled).await;
            offer.owner.cancel();
        } else {
            self.answer(&offer.bot_token, query_id, "This request is closed.").await;
        }
    }

    /// What the heartbeat carries. Expired offers are dropped here, with their buttons.
    pub fn beat(&self) -> Vec<TapView> {
        let now = self.now();
        let mut out = Vec::new();
        let mut expired = Vec::new();
        {
            let mut offers = self.offers();
            offers.retain(|_, o| {
                if now > o.expires_at {
                    expired.push(o.clone());
                    return false;
                }
                true
            });
            for o in offers.values() {
                // A decision is the firewall's own; the console has no dialog for it.
                if o.lines.is_some() {
                    continue;
                }
                out.push(TapView {
                    change_id: o.change_id.clone(),
                    number: o.number.clone(),
                    state: o.state,
                    expires_at: cc_crypto::store_health::iso_from_millis(o.expires_at),
                    code: (o.state == TapState::Approved).then(|| o.code.clone()),
                });
            }
        }
        for o in expired {
            if o.lines.is_some() && o.state == TapState::Open {
                o.owner.cancel();
            }
            let words = o
                .lines
                .as_ref()
                .map(|l| l.expired.clone())
                .unwrap_or_else(|| "This request expired. Nothing was changed.".into());
            let telegram = self.opts.telegram.clone();
            // `void this.edit(...)`: the beat does not wait for Telegram.
            tokio::spawn(async move { edit_with(telegram.as_ref(), &o, &words).await });
        }
        out
    }

    async fn edit(&self, offer: &Offer, line: &str) {
        edit_with(self.opts.telegram.as_ref(), offer, line).await;
    }

    async fn answer(&self, token: &str, query_id: &str, text: &str) {
        if let Err(e) = self
            .opts
            .telegram
            .call(
                token,
                "answerCallbackQuery",
                json!({"callback_query_id": query_id, "text": text}),
            )
            .await
        {
            tracing::info!("[buttons] could not answer a tap: {e}");
        }
    }
}

/// The message as sent, with `line` in place of the button words. A message that cannot be laid
/// out again keeps its text and loses its buttons.
async fn edit_with(telegram: &dyn TelegramApi, offer: &Offer, line: &str) {
    let result = match (offer.render)(line) {
        Ok(text) => {
            telegram
                .call(
                    &offer.bot_token,
                    "editMessageText",
                    json!({"chat_id": offer.chat_id, "message_id": offer.message_id, "text": text}),
                )
                .await
        }
        Err(_) => {
            telegram
                .call(
                    &offer.bot_token,
                    "editMessageReplyMarkup",
                    json!({"chat_id": offer.chat_id, "message_id": offer.message_id, "reply_markup": {"inline_keyboard": []}}),
                )
                .await
        }
    };
    if let Err(e) = result {
        tracing::info!("[buttons] could not update the message: {e}");
    }
}

/// The loopback service the proxy posts taps to: `POST /` `{botId, queries}` → `{"ok":true}`,
/// decided after the answer. Anything else is a 403 `{"ok":false}`.
pub fn router(buttons: Arc<CodeButtons>) -> cc_http::Router {
    let mut router = cc_http::Router::new(&["taps"]);
    router.route(
        "taps",
        |_, _| true,
        move |req, _| {
            let buttons = buttons.clone();
            async move {
                use http_body_util::BodyExt;
                let refused = || cc_http::full(hyper::StatusCode::FORBIDDEN, "text/plain", "{\"ok\":false}");
                let (parts, body) = req.into_parts();
                let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
                if parts.method != hyper::Method::POST || target != "/" {
                    return refused();
                }
                let Ok(raw) = http_body_util::Limited::new(body, 262_144).collect().await else {
                    return refused();
                };
                let Ok(p) = serde_json::from_slice::<Value>(&raw.to_bytes()) else {
                    return refused();
                };
                let Some(queries) = p
                    .get("queries")
                    .and_then(Value::as_array)
                    .filter(|q| q.len() <= 100)
                    .cloned()
                else {
                    return refused();
                };
                let bot_id = p
                    .get("botId")
                    .and_then(Value::as_str)
                    .filter(|b| !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit()))
                    .map(str::to_string);
                tokio::spawn(async move { buttons.taps(bot_id.as_deref(), &queries).await });
                cc_http::full(hyper::StatusCode::OK, "application/json", "{\"ok\":true}")
            }
        },
    );
    router
}
