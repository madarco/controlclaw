//! `phone.test.ts`: the signature vector, strict decoding, the hook query, and the TwiML list.

#![allow(clippy::unwrap_used)]

use super::twiml::allowed_phone_twiml;
use crate::core::url_form::*;

fn get<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
    form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

const HOOK: &str = "https://firewall.example/hook/hk_test";
const TOKEN: &str = "cccccccccccccccccccccccccccccccc";

fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
    p.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Public test vector: https://www.twilio.com/docs/usage/security
#[test]
fn twilios_official_signature_vector() {
    let form = pairs(&[
        ("CallSid", "CA1234567890ABCDE"),
        ("Caller", "+14158675310"),
        ("Digits", "1234"),
        ("From", "+14158675310"),
        ("To", "+18005551212"),
    ]);
    assert_eq!(
        url_form_signature("12345", "https://example.com/myapp.php?foo=1&bar=2", &form),
        "L/OH5YylLD5NRKLltdqwSvS0BnU="
    );
}

#[test]
fn exact_signatures_strict_decoding_and_the_query_allowlist() {
    let p = decode_form(b"To=%2B14155550123&SpeechResult=caf%C3%A9+%26+tea&NewField=%2520").unwrap();
    assert_eq!(get(&p, "SpeechResult"), Some("café & tea"));
    assert_eq!(get(&p, "NewField"), Some("%20"));
    let url = format!("{HOOK}?callId=x&turnToken=y");
    let expected = {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, TOKEN.as_bytes());
        let m = format!("{url}NewField%20SpeechResultcafé & teaTo+14155550123");
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ring::hmac::sign(&key, m.as_bytes()).as_ref(),
        )
    };
    assert_eq!(url_form_signature(TOKEN, &url, &p), expected);
    assert!(verify_url_form(TOKEN, &url, &p, &expected));
    for wrong in [
        format!("{expected}="),
        "!".repeat(28),
        expected[1..].to_string(),
        String::new(),
    ] {
        assert!(!verify_url_form(TOKEN, &url, &p, &wrong));
    }
    assert!(!verify_url_form(TOKEN, HOOK, &p, &expected));
    assert!(!verify_url_form("wrong", &url, &p, &expected));
    for invalid in ["a=1&a=2", "a=%", "a=%FF", "=x", "a=%00"] {
        assert!(decode_form(invalid.as_bytes()).is_err(), "{invalid}");
    }
    assert_eq!(
        hook_query("/hook/hk?callId=abc&type=status").unwrap(),
        "?callId=abc&type=status"
    );
    for q in [
        "?url=https://evil.test",
        "?type=other",
        "?callId=a&callId=b",
        "?turnToken=%0A",
    ] {
        assert!(hook_query(&format!("/hook/hk{q}")).is_err(), "{q}");
    }
}

#[test]
fn twiml_restricts_both_verbs_and_every_callback() {
    for xml in [
        "<Response/>".to_string(),
        r#"<Response><Say voice="alice">Hello &amp; welcome</Say><Pause length="1"/><Hangup/></Response>"#.into(),
        format!(
            r#"<Response><Gather input="speech" action="{HOOK}?callId=x" method="POST"/><Redirect>{HOOK}?callId=x</Redirect></Response>"#
        ),
        r##"<Response><Play digits="12#wW"/></Response>"##.into(),
        r#"<Response><Reject reason="busy"/></Response>"#.into(),
    ] {
        assert!(allowed_phone_twiml(&xml, HOOK), "{xml}");
    }
    for xml in [
        "<Response><Dial>+123456789</Dial></Response>".to_string(),
        r#"<Response><Connect><Stream url="wss://evil"/></Connect></Response>"#.into(),
        "<Response><Play>https://evil.test/audio</Play></Response>".into(),
        r#"<Response><Gather action="https://evil.test"/></Response>"#.into(),
        "<!DOCTYPE Response><Response/>".into(),
        "<Response><Say>&xx;</Say></Response>".into(),
        "<Response/><Response/>".into(),
        "<Response><Say></Response>".into(),
        format!(r#"<Response><Redirect method="GET">{HOOK}</Redirect></Response>"#),
        r#"<Response><Say><Play digits="123"/></Say></Response>"#.into(),
    ] {
        assert!(!allowed_phone_twiml(&xml, HOOK), "{xml}");
    }
}

/// Whitespace as JavaScript has it: U+FEFF is, U+0085 is not (checked against `phone-policy.ts`).
#[test]
fn twiml_whitespace_is_javascripts() {
    for (xml, ok) in [
        ("<Response><Hangup/></Response>\u{feff}", true),
        ("<Response><Hangup/></Response>\u{85}", false),
        ("\u{feff}<?xml version=\"1.0\"?><Response><Hangup/></Response>", true),
        ("<Response><Say>hi</Say>\u{feff}</Response>", true),
        ("<Response\u{feff}><Hangup/></Response>", true),
    ] {
        assert_eq!(allowed_phone_twiml(xml, HOOK), ok, "{xml:?}");
    }
}
