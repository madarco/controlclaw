//! The agent's own storage, the encrypted container behind `~/.openclaw`, and making it larger
//! (`storage.ts`, `routes/storage.ts`, `disk-reseal.ts`, `routes/disk.ts`). `cc-secure` does the
//! work as root behind narrow sudoers lines; this passes a number or a key and reads the answer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cc_http::{BodyBinding, FirewallBody, FirewallRequest, ReadBody, Req, Resp};
use cc_proc::Runner;
use serde_json::{Map, Value, json};

use super::exec::{ExecErr, exec};
use super::web::send_json;

const HELPER: &str = "/usr/local/bin/cc-secure";
const SIZE_TIMEOUT: Duration = Duration::from_secs(15);
/// A grow takes about three seconds; it can wait up to 90 s for the lock.
const GROW_TIMEOUT: Duration = Duration::from_secs(150);
const RESEAL_TIMEOUT: Duration = Duration::from_secs(150);

pub const MIN_TARGET_GB: i64 = 1;
pub const MAX_TARGET_GB: i64 = 9999;

pub const STORAGE_UNSUPPORTED_MESSAGE: &str =
    "This agent was built before storage could be added. Update the agent to add storage.";

/// `UNSUPPORTED_RE`: sudo with no line for it, or an older `cc-secure`.
fn unsupported_text(s: &str) -> bool {
    let l = s.to_lowercase();
    [
        "a password is required",
        "a terminal is required",
        "command not found",
        "cc-secure: no such file",
        "usage: cc-secure {",
    ]
    .iter()
    .any(|p| l.contains(p))
}

fn looks_unsupported(e: &ExecErr) -> bool {
    e.not_found || unsupported_text(&format!("{}\n{}", e.stderr, e.stdout))
}

/// `helperReason`: the last `cc-secure: …` line, capitalised and ended with a full stop.
pub fn helper_reason(e: &ExecErr) -> Option<String> {
    let last = e
        .stderr
        .split('\n')
        .map(str::trim)
        .rfind(|l| l.starts_with("cc-secure: "))?;
    let text = last["cc-secure: ".len()..].trim();
    let mut chars = text.chars();
    let first = chars.next()?;
    let mut out: String = first.to_uppercase().chain(chars).collect();
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    Some(out)
}

/// The last line of `text` that starts with `{`.
fn json_line(text: &str) -> Option<Map<String, Value>> {
    let line = text.split('\n').map(str::trim).rfind(|l| l.starts_with('{'))?;
    match serde_json::from_str::<Value>(line) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// `num`: a finite, non-negative number.
fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|f| f.is_finite() && *f >= 0.0)
}

fn number(f: f64) -> Value {
    if f.fract() == 0.0 && f < 9e15 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

/// `parseSize`: what `cc-secure size` prints, or `None` when the text is not that.
pub fn parse_size(text: &str) -> Option<Value> {
    let o = json_line(text)?;
    if o.get("present") == Some(&Value::Bool(false)) {
        return Some(
            json!({"present": false, "mounted": false, "sizeGb": 0, "maxGb": 0, "reserveGb": 0, "diskBytes": 0,
            "systemUsedBytes": 0, "imageBytes": 0, "fsBytes": null, "usedBytes": null, "freeBytes": null, "pending": false}),
        );
    }
    let size = num(o.get("sizeGb"))?;
    let max = num(o.get("maxGb"))?;
    let disk = num(o.get("diskBytes"))?;
    if o.get("present") != Some(&Value::Bool(true)) || size.fract() != 0.0 || max.fract() != 0.0 || max < size {
        return None;
    }
    let mounted = o.get("mounted") == Some(&Value::Bool(true));
    let inside = |k: &str| if mounted { num(o.get(k)).map(number) } else { None };
    Some(json!({
        "present": true,
        "mounted": mounted,
        "sizeGb": number(size),
        "maxGb": number(max),
        "reserveGb": number(num(o.get("reserveGb")).unwrap_or(0.0)),
        "diskBytes": number(disk),
        "systemUsedBytes": number(num(o.get("systemUsedBytes")).unwrap_or(0.0)),
        "imageBytes": number(num(o.get("imageBytes")).unwrap_or(0.0)),
        "fsBytes": inside("fsBytes"),
        "usedBytes": inside("usedBytes"),
        "freeBytes": inside("freeBytes"),
        "pending": o.get("pending") == Some(&Value::Bool(true)),
    }))
}

/// A refusal with its status and code (`StorageError`, `StorageUnsupportedError`, `ResealError`).
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

fn refusal(status: u16, code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        status,
        code,
        message: message.into(),
    }
}

fn unsupported() -> Refusal {
    refusal(409, "unsupported", STORAGE_UNSUPPORTED_MESSAGE)
}

/// `validTargetGb`: a whole number cc-secure could be given at all.
pub fn valid_target_gb(v: Option<&Value>) -> Option<i64> {
    let f = v?.as_f64()?;
    (f.fract() == 0.0 && f >= MIN_TARGET_GB as f64 && f <= MAX_TARGET_GB as f64).then_some(f as i64)
}

pub struct Storage {
    runner: Arc<dyn Runner>,
    growing: AtomicBool,
    resealing: AtomicBool,
}

/// Clears a busy flag however the run ends.
struct Busy<'a>(&'a AtomicBool);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Storage {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Self {
            runner,
            growing: AtomicBool::new(false),
            resealing: AtomicBool::new(false),
        }
    }

    pub async fn read(&self) -> Result<Value, Refusal> {
        match exec(
            self.runner.as_ref(),
            "sudo",
            &["-n", HELPER, "size"],
            SIZE_TIMEOUT,
            None,
        )
        .await
        {
            Ok(out) => parse_size(&out.stdout).ok_or_else(|| refusal(500, "failed", "The storage could not be read.")),
            Err(e) if looks_unsupported(&e) => Err(unsupported()),
            Err(e) => Err(refusal(
                500,
                "failed",
                helper_reason(&e).unwrap_or_else(|| "The storage could not be read.".into()),
            )),
        }
    }

    /// One at a time on this box; the number is checked here, by the sudoers pattern and by cc-secure.
    pub async fn grow(&self, target: Option<&Value>) -> Result<Value, Refusal> {
        let Some(gb) = valid_target_gb(target) else {
            return Err(refusal(400, "invalid", "The size must be a whole number of GiB."));
        };
        if self.growing.swap(true, Ordering::SeqCst) {
            return Err(refusal(409, "busy", "The storage is already being made larger."));
        }
        let _busy = Busy(&self.growing);
        let gbs = gb.to_string();
        match exec(
            self.runner.as_ref(),
            "sudo",
            &["-n", HELPER, "grow", &gbs],
            GROW_TIMEOUT,
            None,
        )
        .await
        {
            Ok(out) => {
                tracing::info!("[storage] grown to {gb} GiB");
                match parse_size(&out.stdout) {
                    Some(v) => Ok(v),
                    None => self.read().await,
                }
            }
            Err(e) if looks_unsupported(&e) => Err(unsupported()),
            Err(e) => {
                let reason = helper_reason(&e);
                tracing::info!(
                    "[storage] grow to {gb} GiB did not finish: {}",
                    reason.as_deref().unwrap_or("no reason given")
                );
                Err(match reason {
                    Some(r) => refusal(422, "refused", r),
                    None => refusal(500, "failed", "The storage could not be made larger."),
                })
            }
        }
    }

    /// `DiskResealService.reseal`: seal the disk passphrase to a new recovery key.
    pub async fn reseal(&self, public_key: Option<&Value>) -> Result<Value, Refusal> {
        let key = public_key.and_then(Value::as_str).filter(|k| is_recovery_public_key(k));
        let Some(key) = key else {
            return Err(refusal(400, "invalid", "That is not a recovery public key."));
        };
        if self.resealing.swap(true, Ordering::SeqCst) {
            return Err(refusal(409, "busy", "This box is sealing its disk passphrase already."));
        }
        let _busy = Busy(&self.resealing);
        let out = match exec(
            self.runner.as_ref(),
            "sudo",
            &["-n", HELPER, "reseal", key],
            RESEAL_TIMEOUT,
            None,
        )
        .await
        {
            Ok(out) => out,
            Err(e) if looks_unsupported(&e) => {
                return Err(refusal(
                    409,
                    "unsupported",
                    "This box was built before its disk could be sealed to a new recovery key. Update it.",
                ));
            }
            Err(e) => {
                let reason = helper_reason(&e);
                if let Some(r) = &reason
                    && r.to_lowercase().contains("disk is not open")
                {
                    return Err(refusal(409, "locked", r.clone()));
                }
                return Err(refusal(
                    422,
                    "failed",
                    reason.unwrap_or_else(|| {
                        "The disk passphrase could not be sealed to the new recovery key. The old one still opens this disk."
                            .into()
                    }),
                ));
            }
        };
        parse_reseal(&out.stdout).ok_or_else(|| {
            refusal(
                500,
                "failed",
                "The box did not say which recovery key its disk is sealed to now.",
            )
        })
    }
}

/// `RECOVERY_PUBLIC_KEY_RE`: 32 bytes in base64.
pub fn is_recovery_public_key(k: &str) -> bool {
    k.len() == 44
        && k.ends_with('=')
        && k[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// `parseReseal`: `{to: "sha256:<16 hex>", changed}`.
pub fn parse_reseal(text: &str) -> Option<Value> {
    let o = json_line(text)?;
    let to = o.get("to").and_then(Value::as_str)?;
    let tag_ok = to
        .strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    let changed = o.get("changed").and_then(Value::as_bool)?;
    tag_ok.then(|| json!({"to": to, "changed": changed}))
}

/// `handleStorage`: behind the console's token, which the gate already checked.
pub async fn handle_storage(storage: &Storage, req: Req) -> Resp {
    let pathname = cc_http::pathname(&req.uri().to_string());
    let get = req.method() == http::Method::GET;
    let post = req.method() == http::Method::POST;
    let result = match pathname.as_str() {
        "/storage" if get => storage.read().await,
        "/storage/grow" if post => {
            let body = cc_http::read_json_body(req.into_body(), 1024, &BodyBinding::not_firewall()).await;
            storage.grow(body.as_ref().and_then(|b| b.get("targetGb"))).await
        }
        _ => return send_json(404, &json!({"error": "Not found"}), &[]),
    };
    match result {
        Ok(v) => send_json(200, &v, &[]),
        Err(r) => send_json(r.status, &json!({"error": r.message, "code": r.code}), &[]),
    }
}

/// `handleDisk`: `POST /disk/reseal {publicKey}`, firewall-signed with purpose `disk` only.
pub async fn handle_disk(app: &crate::app::App, storage: &Storage, req: Req) -> Resp {
    let read = ReadBody::Json { limit: 1024 };
    let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, "disk", 0, read).await {
        FirewallRequest::Refused { .. } => {
            return send_json(
                401,
                &json!({"error": "a new recovery key must come from the org firewall"}),
                &[],
            );
        }
        FirewallRequest::Accepted { parts, body, .. } => (parts, body),
    };
    if cc_http::pathname(&parts.uri.to_string()) != "/disk/reseal" || parts.method != http::Method::POST {
        return send_json(404, &json!({"error": "Not found"}), &[]);
    }
    // `body?.publicKey`: a refused body reads as no key.
    let key = match &body {
        FirewallBody::Json(b) => b.get("publicKey").cloned(),
        _ => None,
    };
    match storage.reseal(key.as_ref()).await {
        Ok(v) => {
            let changed = v["changed"] == true;
            tracing::info!(
                "[disk] sealed to the recovery key {}{}",
                v["to"].as_str().unwrap_or_default(),
                if changed { "" } else { " (already was)" }
            );
            let mut out = Map::new();
            out.insert("ok".into(), json!(true));
            if let Value::Object(m) = v {
                out.extend(m);
            }
            send_json(200, &Value::Object(out), &[])
        }
        Err(r) => send_json(r.status, &json!({"ok": false, "error": r.message, "code": r.code}), &[]),
    }
}

#[cfg(test)]
mod tests;
