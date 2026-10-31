//! The store round trip with the TS build: every store this folder writes is loaded and saved
//! again by its Rust module, from files the TS sealed, and read back by the TS
//! (the driver is `rust/conformance/cases/w3/store-roundtrip.ts`, which sets `CC_STORE_DIR`; run it
//! from the repo root with `npx tsx rust/conformance/cases/w3/store-roundtrip.ts rust`).

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::agent_client::AgentClient;
use super::identities::Agents;
use super::kit::Kit;

const ORG: &str = "org_rt";
const BOX: &str = "fw_rt";

fn kit(agent: &AgentClient) -> Kit {
    let consent =
        super::consent::Consent::for_tests(agent.clone(), Arc::new(|| None), Arc::new(super::now_ms), "123456");
    Kit {
        consent: crate::contracts::CodeService::module(&super::consent::ConsentView(consent), "roundtrip"),
        routes: Arc::new(|| None),
    }
}

fn p(dir: &Path, f: &str) -> PathBuf {
    dir.join(f)
}

#[test]
#[ignore]
fn store_roundtrip() {
    let Ok(dir) = std::env::var("CC_STORE_DIR") else { return };
    let dir = PathBuf::from(dir);
    let key = std::fs::read_to_string(dir.join("box_key"))
        .expect("box_key")
        .trim()
        .to_string();
    let keys_dir = tempfile::tempdir().expect("keys");
    cc_auth::keys::ensure_vm_keypair(keys_dir.path());
    let agents = Arc::new(Agents::default());
    let agent = AgentClient::for_tests(
        cc_auth::keys::KeysDir::new(keys_dir.path()),
        agents.clone(),
        Arc::new(|_| None),
    );
    let k = kit(&agent);
    let noop = || -> cc_http::BoxFuture<Result<(), String>> { Box::pin(async { Ok(()) }) };

    super::kill::Kill::new(
        p(&dir, "kill.enc"),
        &key,
        ORG,
        BOX,
        agent.clone(),
        k.clone(),
        Arc::new(noop),
    )
    .resave();
    super::tailscale::Tailscale::new(
        p(&dir, "tailscale.enc"),
        &key,
        ORG,
        BOX,
        agent.clone(),
        k.clone(),
        Arc::new(noop),
    )
    .resave();
    super::exit::Exit::new(p(&dir, "exit.enc"), &key, ORG, BOX, k.clone(), Arc::new(noop)).resave();
    super::search::Search::new(
        p(&dir, "search.enc"),
        &key,
        ORG,
        BOX,
        agent.clone(),
        k.clone(),
        false,
        Arc::new(noop),
    )
    .resave();
    super::gbrain::Brain::new(
        p(&dir, "gbrain.enc"),
        &key,
        ORG,
        BOX,
        agent.clone(),
        k.clone(),
        Arc::new(Vec::new),
        Arc::new(|| (false, Vec::new())),
    )
    .resave();
    super::webhooks::Webhooks::new(
        p(&dir, "webhooks.enc"),
        &key,
        ORG,
        BOX,
        agent.clone(),
        k.consent.clone(),
        Arc::new(|| None),
    )
    .resave();
    let access = super::access_store::AccessStoreFile::new(&p(&dir, "access.enc"), &key, ORG, BOX);
    access.save(&access.load()).expect("access");
    super::backup::Backup::new(
        p(&dir, "backup.enc"),
        &key,
        ORG,
        BOX,
        agent.clone(),
        k.clone(),
        None,
        None,
    )
    .resave();
    super::update_all::GrantStore::new(p(&dir, "update-all.enc"), &key, ORG, BOX).resave();
    super::auto_update::AutoUpdateStore::new(p(&dir, "auto-update.enc"), &key, ORG, BOX).resave();
    super::recovery_notices::RecoveryNotices::new(
        p(&dir, "recovery-notices.enc"),
        &key,
        ORG,
        BOX,
        agent.clone(),
        k.clone(),
        Arc::new(|| None),
    )
    .resave();
    super::disk_reseal::DiskReseal::new(
        p(&dir, "disk-reseal.enc"),
        &key,
        ORG,
        BOX,
        agent.clone(),
        k,
        Arc::new(cc_proc::RecordingRunner::new()),
        Arc::new(|| None),
        Arc::new(Vec::new),
        Arc::new(|| Some(Vec::new())),
        Arc::new(|| false),
    )
    .resave();
}
