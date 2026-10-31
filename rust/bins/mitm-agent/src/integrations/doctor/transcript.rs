//! How a transcript event is drawn (`transcript-page.ts`), shared by the firewall's own pages so
//! both read the same: Doctor's chat (`page/chat.js` starts with it) and the AI review history
//! (W4's `ai-review-history`). Plain DOM, text nodes only: event text is never HTML. Served inside
//! each page's own script, because the pages' CSP allows only same-origin scripts. `page/transcript.js`
//! is the TS's `TRANSCRIPT_JS`, written by `tsx`.

#[allow(dead_code)]
pub const TRANSCRIPT_JS: &str = include_str!("page/transcript.js");
/// The box the events are drawn in, and the line shown while it is empty: for the AI review
/// history (W4); Doctor's chat has its own markup.
#[allow(dead_code)]
pub const TRANSCRIPT_BOX: &str = "min-h-[200px] min-w-0 rounded-xl border border-line p-4 sm:p-6";
#[allow(dead_code)]
pub const TRANSCRIPT_EMPTY: &str = "text-[14px] text-ink-2";

#[cfg(test)]
mod tests {
    #[test]
    fn the_chat_script_draws_events_with_the_shared_renderer() {
        assert!(include_str!("page/chat.js").starts_with(super::TRANSCRIPT_JS));
        assert!(super::TRANSCRIPT_JS.contains("textContent"));
        assert!(!super::TRANSCRIPT_JS.contains("innerHTML"));
    }
}
