//! Authentication shared by the agents: the JWTs the console, the firewall and the boxes sign, and
//! the checks the TS agents make on them. Behaviour follows `packages/vm-agent/src/auth.ts` and
//! `packages/mitm-agent/src/{box-token,agent-client}.ts`; see appendix A §2 of the plan.

pub mod console;
pub mod firewall;
pub mod jwt;
pub mod keys;
pub mod sign;
pub mod ticket;

/// `new URL(url, "http://box").pathname`: dot segments resolved, percent-encoding as WHATWG does,
/// query and fragment dropped. `None` where the TS would throw.
pub fn request_path(url: &str) -> Option<String> {
    let base = url::Url::parse("http://box").ok()?;
    base.join(url).ok().map(|u| u.path().to_string())
}

#[cfg(test)]
mod tests {
    use super::request_path;

    #[test]
    fn paths_like_whatwg() {
        assert_eq!(request_path("/a/../b?x").as_deref(), Some("/b"));
        assert_eq!(request_path("/a%20b").as_deref(), Some("/a%20b"));
        assert_eq!(request_path("/a b").as_deref(), Some("/a%20b"));
        assert_eq!(request_path("http://other/x").as_deref(), Some("/x"));
        assert_eq!(request_path("").as_deref(), Some("/"));
    }
}
