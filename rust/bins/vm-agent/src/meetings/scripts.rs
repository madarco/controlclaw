//! The JavaScript the vm-agent runs elsewhere, carried unchanged from the TS in
//! `page_scripts.json` (written by `rust/conformance/cases/w8/page-scripts/gen.mts`): the caption
//! observer and the microphone settings in the meeting browser's pages, and the notes program in
//! `node`.

use std::sync::LazyLock;

#[derive(serde::Deserialize)]
struct Scripts {
    caption: String,
    mic: String,
    notes: String,
}

static SCRIPTS: LazyLock<Scripts> =
    LazyLock::new(|| serde_json::from_str(include_str!("page_scripts.json")).expect("page_scripts.json"));

/// `CAPTION_SCRIPT` (meeting-captions.ts).
pub fn caption() -> &'static str {
    &SCRIPTS.caption
}

/// `MIC_SCRIPT` (meeting-mic.ts).
pub fn mic() -> &'static str {
    &SCRIPTS.mic
}

/// `NOTES_PROGRAM` (meeting-summary.ts).
pub fn notes() -> &'static str {
    &SCRIPTS.notes
}
