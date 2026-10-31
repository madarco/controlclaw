//! Log lines as the Node agents write them: the message alone, info to stdout and warnings and
//! errors to stderr, so the journal (and the Logs pages that read it) look the same.

use tracing_subscriber::fmt::writer::MakeWriterExt;

pub fn init() {
    let writer = std::io::stderr
        .with_max_level(tracing::Level::WARN)
        .or_else(std::io::stdout);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("CC_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .without_time()
        .with_target(false)
        .with_level(false)
        .with_ansi(false)
        .with_writer(writer)
        .try_init();
}
