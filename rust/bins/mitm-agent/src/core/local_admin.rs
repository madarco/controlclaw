//! `mitm-agent reset-admin`: for the operator who forgot the panel's password. It removes the admin,
//! ends every session and prints a fresh one-time setup token (`cc_local::admin::reset`). Run it as
//! the firewall's user (it owns `STATE_DIR/local.db`); the running firewall asks for setup at once.

use std::path::Path;

use cc_local::Db;

pub fn reset_admin() -> ! {
    let fail = |e: String| -> ! {
        eprintln!("mitm-agent reset-admin: {e}");
        std::process::exit(1);
    };
    let state = std::env::var("STATE_DIR").unwrap_or_else(|_| super::env::STANDALONE_STATE_DIR.into());
    let path = Path::new(&state).join(super::local_cp::DB_FILE);
    if !path.exists() {
        // Only a standalone firewall has one (MITM_MODE=standalone).
        fail(format!(
            "{} does not exist: the panel is for a standalone firewall, once it has started",
            path.display()
        ));
    }
    let db = Db::open(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
    let token = cc_local::admin::reset(&db).unwrap_or_else(|e| fail(e));
    println!("{token}");
    eprintln!("The admin password is removed and every session is signed out.");
    eprintln!("Open the panel and set a new password with this one-time setup token.");
    std::process::exit(0);
}
