//! Ported from test_phone.py.

use bytes::Bytes;
use serde_json::{Value, json};

use super::*;
use crate::checks::testkit::{Answer, FakeService};
use crate::checks::{META_BODY_DECODED, META_RECORD};
use crate::flow::testing::request_flow;

const HOOK: &str = "https://firewall.example/hook/hk_test";

fn sid() -> String {
    format!("AC{}", "a".repeat(32))
}
fn ph() -> String {
    format!("CC-TWILIO-{}", "b".repeat(32))
}

fn cred(max: Option<Value>) -> Value {
    let mut phone = json!({"account_sid": sid(), "from_number": "+14155550123", "hook_url": HOOK});
    if let Some(m) = max {
        phone["max_duration"] = m;
    }
    json!({"placeholder": ph(), "secret": "c".repeat(32), "match_domain": "api.twilio.com", "vm_id": "agent-a", "locations": ["basic:authorization"], "phone": phone})
}

fn enc(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                super::super::logins::scope::quote_plus(k, ""),
                super::super::logins::scope::quote_plus(v, "")
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn base_fields() -> Vec<(&'static str, String)> {
    vec![
        ("From", "+14155550123".into()),
        ("To", "+14155550999".into()),
        ("Url", format!("{HOOK}?callId=x")),
        ("StatusCallback", format!("{HOOK}?callId=x&type=status")),
    ]
}

fn flow(body: &str, path: Option<&str>) -> Flow {
    let p = path.map_or_else(|| format!("/2010-04-01/Accounts/{}/Calls.json", sid()), str::to_owned);
    let mut f = request_flow("POST", &format!("https://api.twilio.com{p}"), b"");
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", sid(), ph()))
    );
    f.request = http::Request::builder()
        .method("POST")
        .uri(format!("https://api.twilio.com{p}"))
        .header("authorization", auth)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Bytes::from(body.to_owned()))
        .ok();
    f.vm_id = Some("agent-a".into());
    f.meta.insert(META_BODY_DECODED, json!(true));
    f
}

fn default_flow() -> Flow {
    let f = base_fields();
    flow(&enc(&f.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>()), None)
}

fn form_of(f: &Flow) -> Vec<(String, String)> {
    crate::checks::body::parse_qsl(&String::from_utf8_lossy(
        f.request.as_ref().map(|r| r.body().as_ref()).unwrap_or(b""),
    ))
}

fn get<'a>(form: &'a [(String, String)], k: &str) -> Option<&'a str> {
    form.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

#[test]
fn the_plugins_operations_and_nothing_else() {
    let c = cred(None);
    let mut f = default_flow();
    assert!(authorized(&mut f, &c));
    assert_eq!(get(&form_of(&f), "TimeLimit"), Some("300"));
    for (k, v) in [
        ("Twiml", "<Response><Say>hello</Say></Response>"),
        ("Url", "https://evil.test"),
        ("StatusCallback", "https://evil.test"),
        ("From", "+14155550888"),
        ("To", "sip:evil.test"),
        ("Method", "GET"),
        ("Record", "true"),
    ] {
        let mut fields: Vec<(&str, String)> = base_fields().into_iter().filter(|(a, _)| *a != k).collect();
        fields.push((k, v.into()));
        let mut f = flow(
            &enc(&fields.iter().map(|(a, b)| (*a, b.as_str())).collect::<Vec<_>>()),
            None,
        );
        assert!(!authorized(&mut f, &c), "{k}");
    }
    for p in [
        format!("/2010-04-01/Accounts/{}/Messages.json", sid()),
        format!("/2010-04-01/Accounts/{}.json", sid()),
        format!("/2010-04-01/Accounts/{}/Calls.json?x=y", sid()),
    ] {
        let fields = base_fields();
        let mut f = flow(
            &enc(&fields.iter().map(|(a, b)| (*a, b.as_str())).collect::<Vec<_>>()),
            Some(&p),
        );
        assert!(!authorized(&mut f, &c), "{p}");
    }
    let item = format!("/2010-04-01/Accounts/{}/Calls/CA{}.json", sid(), "d".repeat(32));
    assert!(authorized(&mut flow("Status=completed", Some(&item)), &c));
    assert!(authorized(
        &mut flow(
            &enc(&[("Twiml", r#"<Response><Say>Hi</Say><Play digits="123w#"/></Response>"#)]),
            Some(&item)
        ),
        &c
    ));
    for xml in [
        "<Response><Dial>+14155550888</Dial></Response>",
        r#"<Response><Connect><Stream url="wss://evil.test"/></Connect></Response>"#,
        "<Response><Play>https://evil.test/a</Play></Response>",
        "<!DOCTYPE x><Response/>",
        "<Response><Redirect>https://evil.test</Redirect></Response>",
    ] {
        assert!(
            !authorized(&mut flow(&enc(&[("Twiml", xml)]), Some(&item)), &c),
            "{xml}"
        );
    }
    // Two Authorization headers; a second To.
    let mut f = default_flow();
    let a = f.request.as_ref().map(|r| r.headers()["authorization"].clone());
    if let (Some(r), Some(a)) = (f.request.as_mut(), a) {
        r.headers_mut().append("authorization", a);
    }
    assert!(!authorized(&mut f, &c));
    let body = format!(
        "{}&To=%2B14155550777",
        enc(&base_fields().iter().map(|(a, b)| (*a, b.as_str())).collect::<Vec<_>>())
    );
    assert!(!authorized(&mut flow(&body, None), &c));
    let mut f = default_flow();
    f.sni = Some("evil.test".into());
    assert!(!authorized(&mut f, &c));
    for (d, want) in [(json!(-1), "60"), (json!(600), "600"), (json!(99999), "3600")] {
        let mut f = default_flow();
        assert!(authorized(&mut f, &cred(Some(d))));
        assert_eq!(get(&form_of(&f), "TimeLimit"), Some(want));
    }
}

#[test]
fn twiml() {
    assert!(twiml_allowed("<Response/>", HOOK));
    assert!(twiml_allowed(
        r#"<?xml version="1.0" encoding="UTF-8"?><Response><Gather input="speech" action="https://firewall.example/hook/hk_test?callId=a"><Say>x &amp; y</Say></Gather></Response>"#,
        HOOK
    ));
    for bad in [
        "<Response><Say a='1' a='2'/></Response>",
        "<Response>",
        "<Response/><Response/>",
        "<x:Response/>",
        r#"<Response xmlns="x"/>"#,
        "<Response>&#65;</Response>",
        "<Response><Gather action=\"https://evil/\"/></Response>",
    ] {
        assert!(!twiml_allowed(bad, HOOK), "{bad}");
    }
    assert!(hook_url(&format!("{HOOK}?callId=x&type=status"), HOOK));
    assert!(!hook_url(&format!("{HOOK}?callId=x&callId=y"), HOOK));
    assert!(!hook_url(&format!("{HOOK}?callId=x&"), HOOK));
    assert!(!hook_url(&format!("{HOOK}?other=1"), HOOK));
    assert!(!hook_url(&format!("{HOOK}#f"), HOOK));
}

async fn phone() -> (FakeService, Arc<Phone>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("credentials.json"), json!([cred(None)]).to_string()).expect("creds");
    let svc = FakeService::start().await.expect("svc");
    let p = Arc::new(Phone {
        creds: Arc::new(Creds::new(dir.path().join("credentials.json"))),
        admission_url: svc.url("/"),
    });
    (svc, p, dir)
}

#[tokio::test]
async fn reserve_swap_and_settle() {
    let (svc, p, _dir) = phone().await;
    let reservation = "d".repeat(48);
    svc.answer("/", Answer::json(200, json!({"ok": true, "id": reservation})));
    let mut fields = base_fields();
    fields[2].1.push_str("&ccCall=agent-chosen");
    let mut f = flow(
        &enc(&fields.iter().map(|(a, b)| (*a, b.as_str())).collect::<Vec<_>>()),
        None,
    );
    assert!(matches!(
        TwilioStep(p.clone()).run(Hook::Request, &mut f).await,
        Verdict::Continue
    ));
    assert_eq!(
        svc.calls("/")[0],
        json!({"action": "reserve", "vmId": "agent-a", "placeholder": ph()})
    );
    for k in ["Url", "StatusCallback"] {
        let v = get(&form_of(&f), k).unwrap_or("").to_owned();
        let q = v.split_once('?').map(|(_, q)| q).unwrap_or("");
        assert_eq!(
            crate::checks::body::parse_qsl(q)
                .iter()
                .filter(|(a, _)| a == "ccCall")
                .map(|(_, b)| b.clone())
                .collect::<Vec<_>>(),
            vec![reservation.clone()]
        );
    }
    TwilioSwap(p.clone()).run(Hook::Request, &mut f).await;
    let want = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", sid(), "c".repeat(32)))
    );
    assert_eq!(
        f.request
            .as_ref()
            .map(|r| r.headers()["authorization"].to_str().unwrap_or("").to_owned()),
        Some(want)
    );
    f.response = Some(crate::checks::raw_response(
        201,
        br#"{"sid": "CA1"}"#.to_vec(),
        "application/json",
    ));
    TwilioSettle(p.clone()).run(Hook::Response, &mut f).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(
        svc.calls("/").pop(),
        Some(json!({"action": "settle", "id": reservation, "sid": "CA1", "rejected": false}))
    );
    // Another agent: refused with the record's rule masking the number.
    let mut f = default_flow();
    f.vm_id = Some("agent-b".into());
    let v = TwilioStep(p.clone()).run(Hook::Request, &mut f).await;
    let Verdict::Answer(r) = v else { panic!("refused") };
    assert_eq!(r.status(), 403);
    assert_eq!(f.meta[META_RECORD]["rule"], "phone: outbound ****0999");
    // The admission service down: refused.
    let down = Arc::new(Phone {
        creds: p.creds.clone(),
        admission_url: "http://127.0.0.1:1/".into(),
    });
    let mut f = default_flow();
    assert!(matches!(
        TwilioStep(down).run(Hook::Request, &mut f).await,
        Verdict::Answer(_)
    ));
}

#[test]
fn only_to_twilio_and_only_with_a_stand_in() {
    // The request names Twilio, but the checked destination is elsewhere: nothing goes in.
    let mut f = default_flow();
    let req = f.request.take();
    let mut lying =
        crate::flow::testing::lying_request_flow("POST", "evil.example.com", "https://api.twilio.com/", b"");
    lying.request = req;
    lying.sni = Some(TWILIO.into());
    lying.vm_id = f.vm_id.clone();
    lying.meta = std::mem::take(&mut f.meta);
    assert!(!authorized(&mut lying, &cred(None)));
    // An entry without a placeholder: `Basic base64("<sid>:")` is not taken.
    let mut c = cred(None);
    c.as_object_mut().map(|o| o.remove("placeholder"));
    let mut f = default_flow();
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:", sid()))
    );
    if let Some(r) = f.request.as_mut() {
        r.headers_mut()
            .insert("authorization", http::HeaderValue::from_str(&auth).expect("header"));
    }
    assert!(!authorized(&mut f, &c));
    assert!(authorized(&mut default_flow(), &cred(None)));
}

#[test]
fn a_compressed_form_is_refused() {
    let mut f = default_flow();
    if let Some(r) = f.request.as_mut() {
        r.headers_mut()
            .insert("content-encoding", http::HeaderValue::from_static("gzip"));
    }
    assert!(!authorized(&mut f, &cred(None)));
    let mut f = default_flow();
    if let Some(r) = f.request.as_mut() {
        r.headers_mut()
            .insert("content-encoding", http::HeaderValue::from_static("identity"));
    }
    assert!(authorized(&mut f, &cred(None)));
}
