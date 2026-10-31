//! The 25 cases of `packages/origin-guard/src/index.test.ts`.

use super::*;
use http::{HeaderMap, HeaderValue};

const BOX: &str = "https://claw.vm.controlclaw.com";
const OTHER_BOX: &str = "https://evil.vm.controlclaw.com";
const CONSOLE: &str = "https://controlclaw.com";

fn facts() -> RequestFacts {
    RequestFacts {
        method: "POST".into(),
        origin: Some(BOX.into()),
        sec_fetch_site: Some("same-origin".into()),
        sec_fetch_mode: Some("cors".into()),
        sec_fetch_dest: Some("empty".into()),
        is_upgrade: false,
        credentialed: true,
    }
}

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

fn allow(list: &[&str]) -> OriginPolicy {
    OriginPolicy::allowing(list.iter().copied())
}

fn nav_allow(list: &[&str]) -> OriginPolicy {
    OriginPolicy {
        allow_top_level_navigation: true,
        ..allow(list)
    }
}

fn denied(reason: OriginDenial, origin: Option<&str>) -> OriginVerdict {
    OriginVerdict::Denied {
        reason,
        origin: origin.map(str::to_string),
    }
}

#[test]
fn the_boxs_own_page_is_allowed() {
    assert_eq!(check_origin(&facts(), &allow(&[BOX])), OriginVerdict::Ok);
}

#[test]
fn another_box_on_the_same_site_is_refused() {
    let f = RequestFacts {
        origin: s(OTHER_BOX),
        sec_fetch_site: s("same-site"),
        ..facts()
    };
    assert_eq!(
        check_origin(&f, &allow(&[BOX])),
        denied(OriginDenial::BadOrigin, Some(OTHER_BOX))
    );
}

#[test]
fn the_console_is_refused_unless_it_is_on_the_list() {
    let f = RequestFacts {
        origin: s(CONSOLE),
        sec_fetch_site: s("same-site"),
        ..facts()
    };
    assert!(!check_origin(&f, &allow(&[BOX])).is_ok());
    assert!(check_origin(&f, &allow(&[BOX, CONSOLE])).is_ok());
}

#[test]
fn a_cross_site_request_is_refused_whatever_its_origin_claims() {
    let f = RequestFacts {
        origin: s(BOX),
        sec_fetch_site: s("cross-site"),
        ..facts()
    };
    assert_eq!(
        check_origin(&f, &allow(&[BOX])),
        denied(OriginDenial::CrossSite, Some(BOX))
    );
}

#[test]
fn a_state_changing_request_with_no_origin_is_refused() {
    let f = RequestFacts {
        origin: None,
        sec_fetch_site: None,
        ..facts()
    };
    assert_eq!(
        check_origin(&f, &allow(&[BOX])),
        denied(OriginDenial::MissingOrigin, None)
    );
}

#[test]
fn a_websocket_handshake_is_state_changing() {
    assert!(is_state_changing("GET", true));
    let f = RequestFacts {
        method: "GET".into(),
        is_upgrade: true,
        origin: s(OTHER_BOX),
        sec_fetch_site: s("same-site"),
        sec_fetch_mode: s("websocket"),
        ..facts()
    };
    assert_eq!(
        check_origin(&f, &allow(&[BOX])),
        denied(OriginDenial::BadOrigin, Some(OTHER_BOX))
    );
}

#[test]
fn a_websocket_handshake_with_no_origin_is_refused_too() {
    let f = RequestFacts {
        method: "GET".into(),
        is_upgrade: true,
        origin: None,
        sec_fetch_site: None,
        ..facts()
    };
    assert!(!check_origin(&f, &allow(&[BOX])).is_ok());
}

#[test]
fn a_read_with_no_origin_passes() {
    let f = RequestFacts {
        method: "GET".into(),
        origin: None,
        sec_fetch_site: s("same-origin"),
        ..facts()
    };
    assert_eq!(check_origin(&f, &allow(&[BOX])), OriginVerdict::Ok);
}

fn navigation(method: &str, origin: Option<&str>, dest: Option<&str>) -> RequestFacts {
    RequestFacts {
        method: method.into(),
        origin: origin.map(str::to_string),
        sec_fetch_site: s("cross-site"),
        sec_fetch_mode: s("navigate"),
        sec_fetch_dest: dest.map(str::to_string),
        ..facts()
    }
}

#[test]
fn a_cross_site_top_level_navigation_passes_only_where_asked() {
    let nav = navigation("GET", None, Some("document"));
    assert!(!check_origin(&nav, &allow(&[BOX])).is_ok());
    assert!(check_origin(&nav, &nav_allow(&[BOX])).is_ok());
}

#[test]
fn a_top_level_navigation_get_passes_whatever_origin() {
    for origin in [None, Some("https://mail.google.com"), Some(OTHER_BOX)] {
        assert!(
            check_origin(&navigation("GET", origin, Some("document")), &nav_allow(&[BOX])).is_ok(),
            "{origin:?}"
        );
    }
    let head = navigation("HEAD", Some("https://mail.google.com"), Some("document"));
    assert!(check_origin(&head, &nav_allow(&[BOX])).is_ok());
    let upgrade = RequestFacts {
        is_upgrade: true,
        ..navigation("GET", Some(OTHER_BOX), Some("document"))
    };
    assert!(!check_origin(&upgrade, &nav_allow(&[BOX])).is_ok());
    let framed = RequestFacts {
        sec_fetch_site: s("same-site"),
        ..navigation("GET", Some(OTHER_BOX), Some("iframe"))
    };
    assert!(!check_origin(&framed, &nav_allow(&[BOX])).is_ok());
}

#[test]
fn allow_top_level_navigation_does_not_readmit_a_post_or_a_frame() {
    let post = navigation("POST", Some(OTHER_BOX), Some("document"));
    assert!(!check_origin(&post, &nav_allow(&[BOX])).is_ok());
    let frame = navigation("GET", None, Some("iframe"));
    assert!(!check_origin(&frame, &nav_allow(&[BOX])).is_ok());
}

/// The header set production refused on 2026-09-26 (a verification link clicked from mail).
fn prod_verify_click() -> RequestFacts {
    RequestFacts {
        credentialed: true,
        ..navigation("GET", None, Some("empty"))
    }
}

#[test]
fn the_verification_link_as_production_saw_it_is_let_through() {
    assert_eq!(
        check_origin(&prod_verify_click(), &nav_allow(&[BOX])),
        OriginVerdict::Ok
    );
    let head = RequestFacts {
        method: "HEAD".into(),
        ..prod_verify_click()
    };
    assert!(check_origin(&head, &nav_allow(&[BOX])).is_ok());
    assert!(!check_origin(&prod_verify_click(), &allow(&[BOX])).is_ok());
}

#[test]
fn a_navigation_with_no_sec_fetch_dest_is_top_level_too() {
    let nav = RequestFacts {
        sec_fetch_dest: None,
        ..prod_verify_click()
    };
    assert!(check_origin(&nav, &nav_allow(&[BOX])).is_ok());
}

#[test]
fn the_wider_navigation_rule_readmits_nothing_that_changes_state_or_embeds_us() {
    let policy = nav_allow(&[BOX]);
    let post_other = RequestFacts {
        method: "POST".into(),
        origin: s(OTHER_BOX),
        ..prod_verify_click()
    };
    assert!(!check_origin(&post_other, &policy).is_ok());
    let post_none = RequestFacts {
        method: "POST".into(),
        origin: None,
        ..prod_verify_click()
    };
    assert!(!check_origin(&post_none, &policy).is_ok());
    for mode in [Some("cors"), Some("no-cors"), Some("same-origin"), None] {
        let f = RequestFacts {
            sec_fetch_mode: mode.map(str::to_string),
            ..prod_verify_click()
        };
        assert!(!check_origin(&f, &policy).is_ok(), "{mode:?}");
    }
    let up = RequestFacts {
        is_upgrade: true,
        ..prod_verify_click()
    };
    assert!(!check_origin(&up, &policy).is_ok());
    for dest in ["iframe", "frame", "fencedframe", "embed", "object"] {
        let f = RequestFacts {
            sec_fetch_dest: s(dest),
            ..prod_verify_click()
        };
        assert!(!check_origin(&f, &policy).is_ok(), "{dest}");
    }
}

#[test]
fn a_request_with_no_cookie_is_nobodys_credentials_to_spend() {
    let f = RequestFacts {
        credentialed: false,
        origin: s(OTHER_BOX),
        sec_fetch_site: s("cross-site"),
        ..facts()
    };
    assert_eq!(check_origin(&f, &allow(&[BOX])), OriginVerdict::Ok);
    let check = OriginPolicy {
        uncredentialed: Uncredentialed::Check,
        ..allow(&[BOX])
    };
    assert!(!check_origin(&f, &check).is_ok());
}

#[test]
fn origins_are_compared_after_normalisation_and_nullish_entries_dropped() {
    assert_eq!(
        normalize_origin(Some("https://Claw.VM.ControlClaw.com:443/whatever")).as_deref(),
        Some(BOX)
    );
    assert_eq!(normalize_origin(Some("null")), None);
    assert_eq!(normalize_origin(Some("")), None);
    let f = RequestFacts {
        origin: s("https://CLAW.vm.controlclaw.com:443"),
        ..facts()
    };
    let policy = OriginPolicy {
        allowed: vec![None, None, s(BOX)],
        ..OriginPolicy::default()
    };
    assert!(check_origin(&f, &policy).is_ok());
}

#[test]
fn an_empty_allowlist_refuses_every_origin() {
    let policy = OriginPolicy {
        allowed: vec![None, None],
        ..OriginPolicy::default()
    };
    assert!(!check_origin(&facts(), &policy).is_ok());
}

#[test]
fn a_port_that_is_not_the_default_is_part_of_the_origin() {
    let f = |o: &str| RequestFacts {
        origin: s(o),
        ..facts()
    };
    assert!(check_origin(&f("http://localhost:3000"), &allow(&["http://localhost:3000"])).is_ok());
    assert!(!check_origin(&f("http://localhost:3001"), &allow(&["http://localhost:3000"])).is_ok());
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(*k, HeaderValue::from_str(v).expect("header value"));
    }
    h
}

#[test]
fn agent_facts_take_the_real_method_from_x_forwarded_method() {
    let h = headers(&[
        ("x-forwarded-method", "POST"),
        ("origin", BOX),
        ("cookie", "a=b"),
        ("sec-fetch-site", "same-origin"),
    ]);
    let f = agent_request_facts("GET", &h, None);
    assert_eq!(f.method, "POST");
    assert!(is_state_changing(&f.method, f.is_upgrade));
    assert!(f.credentialed);
    assert_eq!(agent_request_facts("get", &HeaderMap::new(), None).method, "GET");
}

#[test]
fn agent_facts_see_a_websocket_upgrade_and_a_repeated_header() {
    let h = headers(&[("upgrade", "WebSocket"), ("origin", BOX), ("origin", OTHER_BOX)]);
    let f = agent_request_facts("GET", &h, None);
    assert!(f.is_upgrade);
    // node:http joins a repeated Origin into one value, which then matches no allowed origin.
    // (The TS test passes an array and reads its first entry; on the wire this is what arrives.)
    assert_eq!(f.origin.as_deref(), Some(format!("{BOX}, {OTHER_BOX}").as_str()));
    assert!(!f.credentialed);
}

#[test]
fn fetch_facts_read_the_same_headers() {
    let h = headers(&[
        ("origin", CONSOLE),
        ("cookie", "s=1"),
        ("sec-fetch-site", "same-origin"),
        ("x-forwarded-method", "GET"),
    ]);
    let f = fetch_request_facts("POST", &h);
    assert_eq!(f.origin.as_deref(), Some(CONSOLE));
    assert!(f.credentialed);
    assert_eq!(f.method, "POST");
}

#[test]
fn request_origin_rebuilds_the_origin_from_host_alone() {
    assert_eq!(request_origin(Some("controlclaw.com"), None).as_deref(), Some(CONSOLE));
    assert_eq!(
        request_origin(Some("preview.vercel.app"), Some("https,http")).as_deref(),
        Some("https://preview.vercel.app")
    );
    assert_eq!(
        request_origin(Some("localhost:3000"), Some("http")).as_deref(),
        Some("http://localhost:3000")
    );
    assert_eq!(request_origin(None, None), None);
}

#[test]
fn a_forged_x_forwarded_host_does_not_widen_anything() {
    // `request_origin` takes no forwarded host at all; the console origin is what the check gets.
    let f = RequestFacts {
        origin: s(OTHER_BOX),
        ..facts()
    };
    let policy = OriginPolicy {
        allowed: vec![request_origin(Some("controlclaw.com"), None)],
        ..OriginPolicy::default()
    };
    assert!(!check_origin(&f, &policy).is_ok());
}

#[test]
fn a_tossed_duplicate_cookie_reads_as_no_cookie_at_all() {
    let n = "__Secure-cc_view";
    assert_eq!(
        read_unique_cookie(Some("__Secure-cc_view=real"), n),
        CookieReading {
            value: s("real"),
            duplicated: false
        }
    );
    assert_eq!(
        read_unique_cookie(Some("__Secure-cc_view=tossed; __Secure-cc_view=real"), n),
        CookieReading {
            value: None,
            duplicated: true
        }
    );
    assert_eq!(
        read_unique_cookie(Some("other=1"), n),
        CookieReading {
            value: None,
            duplicated: false
        }
    );
    assert_eq!(
        read_unique_cookie(None, n),
        CookieReading {
            value: None,
            duplicated: false
        }
    );
}

#[test]
fn cookie_values_split_on_the_first_equals_only() {
    assert_eq!(cookie_values(Some("t=a.b.c; t2=x"), "t"), vec!["a.b.c"]);
    assert!(cookie_values(Some("cc_session=1"), "session").is_empty());
    assert_eq!(cookie_values(Some("=orphan; t=ok"), "t"), vec!["ok"]);
}
