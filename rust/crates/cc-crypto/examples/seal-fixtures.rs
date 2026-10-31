//! Writes `<dir>/rust-sealed.json`, sealed by the Rust code, for `fixtures/check.mts` to open with the TS.
//!   cargo run -p cc-crypto --example seal-fixtures -- <dir>

include!("../fixtures/inputs.rs");

fn main() {
    let dir = std::env::args().nth(1).expect("usage: seal-fixtures <dir>");
    std::fs::create_dir_all(&dir).expect("create dir");
    let path = std::path::Path::new(&dir).join("rust-sealed.json");
    let fixtures = seal_with_rust();
    // Sanity: Rust opens its own fixtures before the TS is asked to.
    let fails = check_with_rust(&fixtures);
    assert!(fails.is_empty(), "Rust cannot open its own fixtures: {fails:?}");
    std::fs::write(&path, serde_json::to_string_pretty(&fixtures).expect("json")).expect("write");
    println!("wrote {}", path.display());
}
