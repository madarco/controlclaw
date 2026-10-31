//! What this box's Ansible was pulled from (`provenance.ts`), and the one thing it decides:
//! whether a confirmation code may go to the control plane instead of a person (the dev route).
//! Read from the root-owned file the role writes from its checkout's git origin; an allow-list,
//! failing closed. There is no variable and no command that turns it on.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

pub const PROVENANCE_PATH: &str = "/etc/controlclaw/provenance";
/// The repos a firewall may be built from and still open the dev code route.
pub const DEV_CONSENT_REPOS: &[&str] = &["https://github.com/madarco/controlclaw-ansible-test.git"];
pub const PROD_ANSIBLE_REPO: &str = "https://github.com/madarco/controlclaw-ansible.git";

static SCP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:[^@/]+@)?([^:/]+):([^/]|$)").expect("regex"));
static SCHEME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9+.-]*://").expect("regex"));
static USERINFO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^@/]+@").expect("regex"));
static SLASHES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/+$").expect("regex"));

fn norm(u: &str) -> String {
    let s = u.trim().to_lowercase();
    // scp style first, while the colon still means "the path starts" (`(?!\/)` in the TS).
    let s = SCP.replace(&s, "$1/$2").into_owned();
    let s = SCHEME.replace(&s, "").into_owned();
    let s = USERINFO.replace(&s, "").into_owned();
    let s = s.strip_suffix(".git").map(str::to_string).unwrap_or(s);
    SLASHES.replace(&s, "").into_owned()
}

/// `sameRepo`: two git remotes as git would resolve them.
pub fn same_repo(a: &str, b: &str) -> bool {
    norm(a) == norm(b)
}

/// `ansibleOrigin`.
pub fn ansible_origin(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let value = text.split('\n').find_map(|l| l.strip_prefix("ANSIBLE_ORIGIN="))?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// `devConsentAllowed`.
pub fn dev_consent_allowed(path: &Path) -> bool {
    ansible_origin(path).is_some_and(|o| DEV_CONSENT_REPOS.iter().any(|r| same_repo(&o, r)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_test_repo_opens_the_route() {
        let d = tempfile::tempdir().expect("dir");
        let at = |name: &str, text: &str| {
            let p = d.path().join(name);
            std::fs::write(&p, text).expect("w");
            p
        };
        assert!(!dev_consent_allowed(&d.path().join("nope")));
        assert!(!dev_consent_allowed(&at("empty", "ANSIBLE_ORIGIN=\n")));
        assert!(!dev_consent_allowed(&at("other", "BOX_ROLE=mitm\n")));
        assert!(!dev_consent_allowed(&at(
            "prod",
            &format!("ANSIBLE_ORIGIN={PROD_ANSIBLE_REPO}\n")
        )));
        for (i, s) in [
            "https://github.com/madarco/controlclaw-ansible-test.git",
            "https://github.com/madarco/controlclaw-ansible-test",
            "https://github.com/madarco/controlclaw-ansible-test/",
            "https://github.com/Madarco/ControlClaw-Ansible-Test.git",
            "git@github.com:madarco/controlclaw-ansible-test.git",
            "ssh://git@github.com/madarco/controlclaw-ansible-test.git",
            "  https://github.com/madarco/controlclaw-ansible-test.git  ",
        ]
        .iter()
        .enumerate()
        {
            assert!(
                dev_consent_allowed(&at(&format!("t{i}"), &format!("ANSIBLE_ORIGIN={s}\n"))),
                "{s}"
            );
        }
        for (i, s) in [
            "https://www.github.com/madarco/controlclaw-ansible.git",
            "https://github.com/madarco/controlclaw-ansible-mirror.git",
            "https://github.com/someone/controlclaw-ansible.git",
            "https://ghproxy.example.com/github.com/madarco/controlclaw-ansible.git",
            "https://gitlab.com/madarco/controlclaw-ansible.git",
            "https://evil.trycloudflare.com/",
            "https://github.com/madarco/controlclaw-ansible-test-2.git",
        ]
        .iter()
        .enumerate()
        {
            assert!(
                !dev_consent_allowed(&at(&format!("l{i}"), &format!("ANSIBLE_ORIGIN={s}\n"))),
                "{s}"
            );
        }
        assert!(!DEV_CONSENT_REPOS.iter().any(|r| same_repo(r, PROD_ANSIBLE_REPO)));
    }
}
