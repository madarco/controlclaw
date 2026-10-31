//! The stand-in for `systemctl`, `sudo` and `journalctl` while a case runs: the runner links them
//! to its own binary in a folder put first on the agent's PATH. Each call is appended to
//! `CC_SHIM_LOG` and answered from the rules in `CC_SHIM_RULES` (first prefix match wins). A call no
//! rule answers fails, so a case never runs a real helper.

use std::io::{Read, Write};

use crate::case::ShimRule;

/// How long a helper waits for its caller to close stdin.
const STDIN_WAIT: std::time::Duration = std::time::Duration::from_millis(200);

/// The programs the rig stands in for.
pub const PROGRAMS: &[&str] = &["systemctl", "sudo", "journalctl"];

/// What every case gets after its own rules: units are not active and do not exist, sudo refuses.
pub fn default_rules() -> Vec<ShimRule> {
    let r = |argv: &[&str], stdout: &str, stderr: &str, code: i32| ShimRule {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdout: stdout.into(),
        stderr: stderr.into(),
        code,
    };
    vec![
        r(&["systemctl", "is-active"], "inactive\n", "", 3),
        r(&["systemctl", "cat"], "", "No files found.\n", 1),
        r(&["systemctl", "status"], "", "Unit could not be found.\n", 4),
        r(&["systemctl", "show"], "", "", 1),
        r(&["journalctl"], "", "", 1),
        r(&["sudo"], "", "sudo: a password is required\n", 1),
    ]
}

pub fn run(program: &str) -> ! {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut argv = vec![program.to_string()];
    argv.extend(args);
    // What the caller sent, so a case can check it (a key on stdin, a config). Node's async
    // `execFile` leaves a child's stdin pipe open when it sends nothing, so the read waits at most
    // STDIN_WAIT for the end and records what came by then.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let stdin = rx.recv_timeout(STDIN_WAIT).unwrap_or_default();
    if let Ok(log) = std::env::var("CC_SHIM_LOG")
        && let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(log)
    {
        let line = serde_json::json!({"argv": argv, "stdin": String::from_utf8_lossy(&stdin)});
        let _ = writeln!(f, "{line}");
    }
    let rules: Vec<ShimRule> = std::env::var("CC_SHIM_RULES")
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default();
    let hit = rules
        .iter()
        .find(|r| r.argv.len() <= argv.len() && r.argv.iter().zip(&argv).all(|(a, b)| a == b));
    match hit {
        Some(r) => {
            print!("{}", r.stdout);
            eprint!("{}", r.stderr);
            let _ = std::io::stdout().flush();
            std::process::exit(r.code)
        }
        None => {
            eprintln!("cc-conformance shim: no rule for {argv:?}");
            std::process::exit(127)
        }
    }
}
