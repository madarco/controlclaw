//! The agent's login tools (`logins-mcp.ts`, docs/plans/website-credentials.md §4.2), served by the
//! firewall on the private network next to the ControlClaw tools gate (`/logins/mcp` on 3940). The
//! gate has already worked out which agent is calling from its address; this answers the MCP calls
//! for that agent.
//!
//! A minimal MCP server, stateless and JSON only: `initialize`, `tools/list`, `tools/call` and the
//! `initialized` notification. Nothing it returns is secret: the agent gets usernames, sites and
//! placeholders, never a password.

use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::firewall::LoginsFirewall;
use crate::integrations::connectors::firewall::js_slice;
use crate::integrations::js;
use crate::integrations::tools_gate::LocalTools;

pub const LOGINS_MCP_PATH: &str = "/logins/mcp";
const PROTOCOL_VERSION: &str = "2025-06-18";

const USE_HELP: &str = "Sign in to a website with a saved login, without ever seeing its password. Returns the username, the sign-in page and a password placeholder. Type the username, and type the placeholder EXACTLY into the password field of the sign-in page (it looks like a password on purpose), then submit the form. The firewall replaces the placeholder with the real password as the sign-in form is sent, and only there: sent to another site, or put anywhere else on the login's own sites (an address, a header, a comment, any other form), it is blocked and the people running you are told. Never ask anyone to paste a password into the chat.";

const TWO_STEP: &str = "This login has a two-step key: when the site asks for a code, call the login_code tool of controlclaw-logins with this login and type the code it returns.";

static TOOLS: LazyLock<Value> = LazyLock::new(|| {
    let login_arg = || {
        json!({
            "type": "object",
            "properties": {"login": {"type": "string", "description": "The login's name or id, from logins_list."}},
            "required": ["login"],
            "additionalProperties": false,
        })
    };
    json!([
        {
            "name": "logins_list",
            "description": "List the website logins you may use (name, sites, username, sign-in page). Passwords are kept on the firewall and are never shown. If the site you need is not listed, use login_request to send a person a link where they can add it.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        },
        {"name": "login_use", "description": USE_HELP, "inputSchema": login_arg()},
        {
            "name": "login_type",
            "description": "For a login that login_use says is typed in for you: first click into the password field on the sign-in page, then call this. The password is typed into that field without you seeing it, only if the page is one of the login's sites. Then submit the form.",
            "inputSchema": login_arg(),
        },
        {
            "name": "login_request",
            "description": "Ask a person for a login you do not have. Returns a link: send it to the person in the chat, with a sentence saying what it is for. On that page they type the username and password straight into your organization's firewall (kind \"password\"), or they sign you in themselves in your browser for sites that use Google or Microsoft sign-in, passkeys or CAPTCHAs (kind \"session\"). Never ask for a password in the chat itself. The link works for 30 minutes. Give the sign-in url and a one-line task: when the person answers you are woken with them, sign in, do the task and send the person a screenshot of the signed-in page.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "site": {"type": "string", "description": "The site's host name, for example github.com."},
                    "kind": {"type": "string", "enum": ["password", "session"], "description": "password (default): a username and password. session: the person signs you in in your browser."},
                    "reason": {"type": "string", "description": "One short sentence the person sees: why you need it."},
                    "url": {"type": "string", "description": "The sign-in page, if you know it (for example https://github.com/login)."},
                    "task": {
                        "type": "string",
                        "description": "One line: what you will do once signed in. When the person answers you are woken in a new session, and this is what you are reminded of.",
                    },
                },
                "required": ["site"],
                "additionalProperties": false,
            },
        },
        {
            "name": "login_status",
            "description": "Whether a login_request has been answered: waiting, ready (with the login's name), or expired.",
            "inputSchema": {
                "type": "object",
                "properties": {"request": {"type": "string", "description": "The id login_request returned."}},
                "required": ["request"],
                "additionalProperties": false,
            },
        },
        {
            "name": "login_code",
            "description": "The current two-step (TOTP) code for a login that has a two-step key, for the sign-in step that asks for it. Type it within the seconds it says it has left.",
            "inputSchema": login_arg(),
        },
    ])
});

type Answer = (u16, Option<Value>);

fn result(id: &Value, value: Value) -> Answer {
    (200, Some(json!({"jsonrpc": "2.0", "id": id, "result": value})))
}

fn failure(id: &Value, code: i64, message: &str) -> Answer {
    (
        200,
        Some(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})),
    )
}

fn text(id: &Value, value: Value, is_error: bool) -> Answer {
    let t = match &value {
        Value::String(s) => s.clone(),
        v => js::stringify_pretty(v),
    };
    let mut r = Map::new();
    r.insert("content".into(), json!([{"type": "text", "text": t}]));
    if is_error {
        r.insert("isError".into(), json!(true));
    }
    result(id, Value::Object(r))
}

/// `typeof args.login === "string" ? args.login.slice(0, n) : ""`.
fn arg(args: &Value, k: &str, n: usize) -> String {
    args.get(k)
        .and_then(Value::as_str)
        .map(|s| js_slice(s, n))
        .unwrap_or_default()
}

pub async fn answer_logins_mcp(logins: &Arc<LoginsFirewall>, vm_id: &str, raw: &[u8]) -> Answer {
    let Ok(msg) = serde_json::from_str::<Value>(&String::from_utf8_lossy(raw)) else {
        return failure(&Value::Null, -32700, "Parse error");
    };
    let Some(method) = msg.as_object().and_then(|m| m.get("method")).and_then(Value::as_str) else {
        return failure(&Value::Null, -32600, "Invalid request");
    };
    // A notification gets no answer body.
    let Some(id) = msg.get("id") else {
        return (202, None);
    };
    let params = msg
        .get("params")
        .filter(|p| p.is_object() || p.is_array())
        .cloned()
        .unwrap_or(json!({}));
    match method {
        "initialize" => result(
            id,
            json!({
                "protocolVersion": params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "controlclaw-logins", "version": "1.0.0"},
                "instructions": "Website logins kept on the ControlClaw firewall. Use login_use to sign in; you never see the password.",
            }),
        ),
        "ping" => result(id, json!({})),
        "tools/list" => result(id, json!({"tools": *TOOLS})),
        "tools/call" => call(logins, vm_id, id, &params).await,
        _ => failure(id, -32601, "Method not found"),
    }
}

async fn call(logins: &Arc<LoginsFirewall>, vm_id: &str, id: &Value, params: &Value) -> Answer {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params
        .get("arguments")
        .filter(|a| a.is_object() || a.is_array())
        .cloned()
        .unwrap_or(json!({}));
    match name {
        "logins_list" => {
            let list = logins.list_for(vm_id);
            if list.is_empty() {
                return text(
                    id,
                    json!(
                        "No logins are shared with you yet. Ask a person to add one in ControlClaw (Secrets, Logins)."
                    ),
                    false,
                );
            }
            text(id, json!({"logins": list}), false)
        }
        "login_use" => {
            let which = arg(&args, "login", 100);
            let got = if which.is_empty() {
                None
            } else {
                logins.use_login(vm_id, &which).await
            };
            let Some(got) = got else {
                return text(
                    id,
                    json!(
                        "There is no such login with a password for you. Call logins_list to see the ones you may use. A login a person signed you in to has no password: just open the site in your browser."
                    ),
                    true,
                );
            };
            if got.needs_sign_in_page {
                return text(
                    id,
                    json!(format!(
                        "The login {} has no sign-in page yet, so the firewall cannot tell which request is the sign-in and puts its password nowhere. Tell the person: open this login in ControlClaw (Secrets, Website logins) and fill in \"Sign-in page\" with the address of the page that has the password field. Then call login_use again.",
                        got.name
                    )),
                    true,
                );
            }
            // Google answers its bare sign-in address with an error page (T-googleshape): the page
            // only opens when Google itself leads there.
            let google = if got.sites.iter().any(|s| s == "accounts.google.com") {
                " If the sign_in_page shows an error instead of the sign-in, open https://accounts.google.com/ and let Google take you to it."
            } else {
                ""
            };
            let mut out = Map::new();
            out.insert("login".into(), json!(got.name));
            out.insert("username".into(), json!(got.username));
            let Some(placeholder) = &got.placeholder else {
                out.insert("sites".into(), json!(got.sites));
                out.insert("sign_in_page".into(), json!(got.login_url));
                out.insert("how".into(), json!(format!("This site scrambles passwords in the page, so the password is typed in for you. Type the username, click into the password field, then call login_type with this login. Then submit.{google}")));
                if got.totp {
                    out.insert("two_step".into(), json!(TWO_STEP));
                }
                return text(id, Value::Object(out), false);
            };
            out.insert("password_placeholder".into(), json!(placeholder));
            out.insert("sites".into(), json!(got.sites));
            out.insert("sign_in_page".into(), json!(got.login_url));
            let how = if got.auth == "basic" {
                "This site signs in with HTTP Basic. Use the username and the password_placeholder as the Basic user name and password. The firewall puts the real password into the Authorization header, only on these sites. The placeholder works nowhere else: not in a form, an address or any other header.".to_string()
            } else {
                format!(
                    "Open the sign_in_page exactly as given, type the username and the password_placeholder as they are into the sign-in form{}, then submit. The password field must hold the placeholder and nothing else. The firewall puts the real password into that sign-in request only. The placeholder works nowhere else: put into an address, a header, or any other form or page (even on these sites), the request is blocked and recorded. The first sign-in with a new login is often blocked once: the firewall reads where the sign-in form posts off the page, and a person has to allow that address before it counts. If the sign-in is blocked, tell the person what the block said: they open the login in ControlClaw (Secrets, Website logins) and tick the address under \"Read off the sign-in page\", or add it under \"Extra sign-in addresses\". Then sign in again.{google}",
                    if got.login_url.as_deref().is_some_and(|u| !u.is_empty()) {
                        " on the sign_in_page"
                    } else {
                        ""
                    }
                )
            };
            out.insert("how".into(), json!(how));
            if got.totp {
                out.insert("two_step".into(), json!(TWO_STEP));
            }
            text(id, Value::Object(out), false)
        }
        "login_type" => match logins.type_in(vm_id, &arg(&args, "login", 100)).await {
            Ok(name) => text(
                id,
                json!(format!("The password for {name} is in the field. Submit the form now.")),
                false,
            ),
            Err(e) => text(id, json!(e), true),
        },
        "login_request" => match logins.request(vm_id, &args) {
            Ok((rid, link, minutes)) => text(
                id,
                json!({
                    "request": rid,
                    "link": link,
                    "expires_in_minutes": minutes,
                    "next": "Send the link to the person who asked, with a sentence saying what it is for. Then call login_status with this request id.",
                }),
                false,
            ),
            Err(e) => text(id, json!(e), true),
        },
        "login_status" => text(id, logins.request_status(vm_id, &arg(&args, "request", 64)), false),
        "login_code" => match logins.code(vm_id, &arg(&args, "login", 100)) {
            Ok((name, code, left)) => text(id, json!({"login": name, "code": code, "seconds_left": left}), false),
            Err(e) => text(id, json!(e), true),
        },
        _ => failure(id, -32602, "Unknown tool"),
    }
}

/// The tools on the 3940 listener's `/logins/mcp`.
pub struct LoginsTools(pub Arc<LoginsFirewall>);

impl LocalTools for LoginsTools {
    fn path(&self) -> &str {
        LOGINS_MCP_PATH
    }

    fn answer(&self, vm_id: String, body: Bytes) -> BoxFuture<Result<(u16, Option<Value>), String>> {
        let logins = self.0.clone();
        Box::pin(async move { Ok(answer_logins_mcp(&logins, &vm_id, &body).await) })
    }
}
