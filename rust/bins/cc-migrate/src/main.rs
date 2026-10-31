//! `cc-migrate`: the store check Ansible runs before it switches a box to the Rust build, and the
//! frame for a later format change (docs/plans/rust-rewrite.md §5.2).
//!
//! `check` opens every store this build knows with the Rust code and says which it cannot read.
//! The port changes no format, so on a healthy box every store opens; a store that does not means
//! the box stays on the Node build. Workstreams list their stores in `stores/<w>.rs`.
//!
//! `up`, `down`, `cleanup` and `status` run the format changes in `steps.rs` (none yet).
//!
//! Every command prints one JSON object on stdout. Exit 0: done or all readable; 1: a store does
//! not open or a step failed; 2: the command line was wrong.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;

mod steps;
mod store;
mod stores;

use store::Role;

#[derive(Parser)]
#[command(about = "Check and migrate a box's stores for the Rust build")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
    /// Which box this is. Required: a firewall checked as an agent would find none of its stores
    /// and pass.
    /// (Optional to clap only because a global argument cannot be required; a missing one is
    /// clap's usage error.)
    #[arg(long, global = true, value_enum)]
    role: Option<Role>,
    /// Put in front of every box path, the box key's and the ledger's included (a test's folder).
    /// `/` on a box; Ansible never sets it.
    #[arg(long, global = true, default_value = "/")]
    root: PathBuf,
    #[arg(
        long,
        global = true,
        env = "BOX_KEY_PATH",
        default_value = "/opt/controlclaw/keys/box_key"
    )]
    box_key: PathBuf,
    #[arg(long, global = true, env = "ORG_ID", default_value = "")]
    org_id: String,
    #[arg(long, global = true, env = "BOX_ID", default_value = "")]
    box_id: String,
    /// Which format changes ran on this box.
    #[arg(long, global = true, default_value = "/opt/controlclaw/state/cc-migrate.json")]
    ledger: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open every store this build reads.
    Check,
    /// Apply the format changes not yet applied.
    Up,
    /// Undo the applied format changes, newest first, down to (not including) `--to`.
    Down {
        #[arg(long)]
        to: Option<String>,
    },
    /// The new build started cleanly: drop the copies `down` would need.
    Cleanup,
    /// Which format changes are applied and which are not.
    Status,
}

fn main() -> ExitCode {
    let a = Args::parse();
    let Some(role) = a.role else {
        use clap::CommandFactory;
        Args::command()
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "--role agent|firewall is required",
            )
            .exit();
    };
    let role_name = format!("{role:?}").to_lowercase();
    let under_root = |p: &PathBuf| a.root.join(p.strip_prefix("/").unwrap_or(p));
    // A key that is there but cannot be read is a failure to say, not a key that is missing; only
    // `check` and the steps need it, so `status`, `cleanup` and a rollback are never blocked by it.
    let needs_key = matches!(a.cmd, Cmd::Check | Cmd::Up | Cmd::Down { .. });
    let key = match std::fs::read_to_string(under_root(&a.box_key)) {
        Ok(k) => Some(k.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || !needs_key => None,
        Err(e) => {
            println!(
                "{}",
                json!({"role": role_name, "error": format!("box key {}: {e}", a.box_key.display())})
            );
            return ExitCode::FAILURE;
        }
    };
    let ledger = under_root(&a.ledger);
    // The commands that change files hold the box's lock from here to the end.
    let _lock = match a.cmd {
        Cmd::Up | Cmd::Down { .. } | Cmd::Cleanup => match steps::lock(&ledger) {
            Ok(f) => Some(f),
            Err(e) => {
                println!("{}", json!({"role": role_name, "error": e}));
                return ExitCode::FAILURE;
            }
        },
        Cmd::Check | Cmd::Status => None,
    };
    let ctx = steps::StepCtx {
        root: &a.root,
        box_key: key.as_deref(),
        org_id: &a.org_id,
        box_id: &a.box_id,
    };
    let (report, ok) = match a.cmd {
        Cmd::Check => {
            let mut stores = Vec::new();
            let mut bad = 0;
            for s in stores::all().filter(|s| s.role == role) {
                let r = store::check_one(s, &a.root, key.as_deref(), (&a.org_id, &a.box_id), &|v| {
                    std::env::var(v).ok()
                });
                bad += usize::from(r.is_err());
                stores.push(match r {
                    Ok(true) => json!({"store": s.name, "ok": true}),
                    Ok(false) => json!({"store": s.name, "ok": true, "absent": true}),
                    Err(e) => json!({"store": s.name, "ok": false, "error": e}),
                });
            }
            (
                json!({"role": role_name, "checked": stores.len(), "unreadable": bad, "stores": stores}),
                bad == 0,
            )
        }
        Cmd::Up => match steps::up(steps::STEPS, role, &ctx, &ledger) {
            Ok(done) => (json!({"role": role_name, "applied": done}), true),
            Err(e) => (json!({"role": role_name, "error": e}), false),
        },
        Cmd::Down { to } => match steps::down(steps::STEPS, role, &ctx, &ledger, to.as_deref()) {
            Ok(done) => (json!({"role": role_name, "undone": done}), true),
            Err(e) => (json!({"role": role_name, "error": e}), false),
        },
        Cmd::Cleanup => match steps::cleanup(steps::STEPS, role, &ctx, &ledger) {
            Ok(n) => (json!({"role": role_name, "removed": n}), true),
            Err(e) => (json!({"role": role_name, "error": e}), false),
        },
        Cmd::Status => match steps::Ledger::load(&ledger) {
            Ok(l) => {
                let mut pending: Vec<&str> = steps::STEPS
                    .iter()
                    .filter(|s| s.role == role && !l.done(s.id))
                    .map(|s| s.id)
                    .collect();
                pending.sort();
                let applied: Vec<_> = l
                    .applied
                    .iter()
                    .filter(|x| x.role == role)
                    .map(|x| json!({"id": x.id, "state": x.state}))
                    .collect();
                (json!({"role": role_name, "applied": applied, "pending": pending}), true)
            }
            Err(e) => (json!({"role": role_name, "error": e}), false),
        },
    };
    println!("{report}");
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

#[cfg(test)]
mod tests {
    use super::store::{Format, Store, check_one};
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn opens_an_enc_file_and_refuses_the_wrong_aad() {
        let d = tempfile::tempdir().expect("dir");
        let key = cc_crypto::secret_store::generate_box_key();
        let path = d.path().join("state/x.enc");
        cc_crypto::enc_file::save_encrypted_json(&path, &json!({"a": 1}), &key, "org_1:fw_1:x").expect("seal");
        let store = Store {
            role: Role::Firewall,
            name: "x",
            path: "/state/x.enc",
            env: None,
            format: Format::EncFile { purpose: "x" },
        };
        assert_eq!(
            check_one(&store, d.path(), Some(&key), ("org_1", "fw_1"), &no_env),
            Ok(true)
        );
        assert!(check_one(&store, d.path(), Some(&key), ("org_1", "fw_2"), &no_env).is_err());
        let missing = Store {
            path: "/state/none.enc",
            ..store
        };
        assert_eq!(
            check_one(&missing, d.path(), Some(&key), ("org_1", "fw_1"), &no_env),
            Ok(false)
        );
    }

    #[test]
    fn the_units_path_wins() {
        let d = tempfile::tempdir().expect("dir");
        std::fs::create_dir_all(d.path().join("elsewhere")).expect("mkdir");
        std::fs::write(d.path().join("elsewhere/w.json"), "{}").expect("write");
        let store = Store {
            role: Role::Firewall,
            name: "w",
            path: "/state/w.json",
            env: Some("WEBHOOKS_PATH"),
            format: Format::Json,
        };
        assert_eq!(check_one(&store, d.path(), None, ("o", "b"), &no_env), Ok(false));
        let unit = |v: &str| (v == "WEBHOOKS_PATH").then(|| "/elsewhere/w.json".to_string());
        assert_eq!(check_one(&store, d.path(), None, ("o", "b"), &unit), Ok(true));
    }
}
