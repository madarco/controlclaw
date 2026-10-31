//! The Rust code opens what the TS code sealed (`fixtures/ts-sealed.json`, made by `fixtures/gen.mts`).
//! The other direction is `examples/seal-fixtures.rs` with `fixtures/check.mts`.
#![allow(clippy::unwrap_used)]

include!("../fixtures/inputs.rs");

#[test]
fn opens_everything_the_ts_sealed() {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/ts-sealed.json")).expect("fixtures");
    let f: Fixtures = serde_json::from_str(&raw).expect("parse");
    assert_eq!(f.sealed_by, "ts");
    let fails = check_with_rust(&f);
    assert!(fails.is_empty(), "{fails:#?}");
}

#[test]
fn opens_what_it_sealed_itself() {
    let fails = check_with_rust(&seal_with_rust());
    assert!(fails.is_empty(), "{fails:#?}");
}
