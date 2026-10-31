//! Print the local panel API's OpenAPI document (`packages/fw-api/openapi.json`).

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&cc_local::api::openapi()).expect("the document is JSON")
    );
}
