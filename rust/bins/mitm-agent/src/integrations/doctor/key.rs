//! Doctor's SSH key (`doctor-key.ts`): one standing ed25519 key the agents install for the
//! `ccdoctor` account, signed by this firewall, and the host key each agent answered with. Kept
//! sealed in `doctor.enc`. An unreadable standing key never silently rotates: dead agents keep the
//! old one.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};

use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const DOCTOR_KEY_DOMAIN: &str = "controlclaw:doctor-key:v1\n";
static HOST_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?$").expect("pattern"));

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    pub pub_: String,
    pub private_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<crate::integrations::ordmap::OrdMap<String>>,
}

/// `{pub, privateKey, agents?}` on disk: `pub` is a keyword here.
mod wire {
    use super::*;
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct K {
        #[serde(rename = "pub")]
        pub p: String,
        pub private_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agents: Option<crate::integrations::ordmap::OrdMap<String>>,
    }
}

pub type Sign = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;
pub type Generate = Arc<dyn Fn() -> Result<(String, String), String> + Send + Sync>;

pub struct DoctorKeyStore {
    path: PathBuf,
    box_key: String,
    aad: String,
    sign: Sign,
    key: Mutex<Key>,
    installed: Mutex<HashSet<String>>,
    reconciling: tokio::sync::Mutex<()>,
}

/// `SHA256:<base64 of the key's blob, unpadded>`, as `ssh-keygen -l` prints it.
pub fn fingerprint(pub_: &str) -> String {
    let blob = pub_
        .split(' ')
        .nth(1)
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .unwrap_or_default();
    let d = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob));
    format!("SHA256:{d}")
}

impl DoctorKeyStore {
    pub fn open(
        path: PathBuf,
        box_key: &str,
        org_id: &str,
        box_id: &str,
        sign: Sign,
        generate: Generate,
    ) -> Result<Self, String> {
        let aad = format!("{org_id}:{box_id}:doctor-key:v1");
        let saved = cc_crypto::enc_file::load_encrypted_json(&path, box_key, &aad)
            .map_err(|_| "the Doctor key store does not open".to_string())?;
        let (key, fresh) = match saved {
            Some(v) => {
                let k: wire::K =
                    serde_json::from_value(v).map_err(|_| "the Doctor key store does not read".to_string())?;
                (
                    Key {
                        pub_: k.p,
                        private_key: k.private_key,
                        agents: k.agents,
                    },
                    false,
                )
            }
            None => {
                let (p, private_key) = generate()?;
                (
                    Key {
                        pub_: p,
                        private_key,
                        agents: None,
                    },
                    true,
                )
            }
        };
        cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(key.private_key.clone()), true);
        let installed: HashSet<String> = key
            .agents
            .as_ref()
            .map(|a| a.keys().cloned().collect())
            .unwrap_or_default();
        let s = Self {
            path,
            box_key: box_key.into(),
            aad,
            sign,
            key: Mutex::new(key),
            installed: Mutex::new(installed),
            reconciling: tokio::sync::Mutex::new(()),
        };
        if fresh {
            s.save()?;
        }
        Ok(s)
    }

    fn save(&self) -> Result<(), String> {
        let k = self.key.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let v = serde_json::to_value(wire::K {
            p: k.pub_,
            private_key: k.private_key,
            agents: k.agents,
        })
        .unwrap_or(Value::Null);
        cc_crypto::enc_file::save_encrypted_json(&self.path, &v, &self.box_key, &self.aad)
            .map_err(|_| "the Doctor key store could not be written".to_string())
    }

    /// `{pub, sig, fingerprint}`: what the agents and the console are given.
    pub fn public_key(&self) -> Value {
        let p = self.key.lock().unwrap_or_else(|e| e.into_inner()).pub_.clone();
        let sig = (self.sign)(&format!("{DOCTOR_KEY_DOMAIN}{p}")).unwrap_or_default();
        json!({"pub": p, "sig": sig, "fingerprint": fingerprint(&p)})
    }

    /// Only for the runner, after a code was confirmed. Never sent to an agent or the console.
    pub fn private_key(&self) -> String {
        self.key.lock().unwrap_or_else(|e| e.into_inner()).private_key.clone()
    }

    pub fn host_key(&self, vm_id: &str) -> Option<String> {
        self.key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .agents
            .as_ref()
            .and_then(|a| a.get(vm_id).cloned())
    }

    pub fn ready(&self, vm_id: &str) -> bool {
        self.installed.lock().unwrap_or_else(|e| e.into_inner()).contains(vm_id)
    }

    /// The agents Doctor can reach, for the beat's `doctor_keys`, in the order they were installed.
    pub fn ready_ids(&self) -> Vec<String> {
        let installed = self.installed.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let k = self.key.lock().unwrap_or_else(|e| e.into_inner());
        k.agents
            .as_ref()
            .map(|a| a.keys().filter(|id| installed.contains(*id)).cloned().collect())
            .unwrap_or_default()
    }

    /// Put the key on every agent that lacks it and learn each one's host key. One agent at a time;
    /// a failed agent is tried again on the next sync. A run while one runs is skipped.
    pub async fn reconcile(&self, targets: &[String], client: &Arc<dyn crate::contracts::AgentClient>) {
        let Ok(_one) = self.reconciling.try_lock() else { return };
        let published = self.public_key();
        let fp = published["fingerprint"].clone();
        self.installed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|id| targets.contains(id));
        for vm in targets {
            let Ok(status) = client.get(vm, "/doctor/status").await else {
                continue;
            };
            if status.get("fingerprint") != Some(&fp) {
                let body = json!({"pub": published["pub"], "sig": published["sig"]});
                let Ok(r) = client.post(vm, "/doctor/key", body).await else {
                    continue;
                };
                if r.get("fingerprint") != Some(&fp) {
                    continue;
                }
            }
            let Some(host) = status
                .get("sshHostKey")
                .and_then(Value::as_str)
                .filter(|h| HOST_KEY.is_match(h))
            else {
                continue;
            };
            {
                let mut k = self.key.lock().unwrap_or_else(|e| e.into_inner());
                k.agents
                    .get_or_insert_with(Default::default)
                    .insert(vm.clone(), host.into());
            }
            if self.save().is_ok() {
                self.installed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(vm.clone());
            }
        }
    }
}

/// `ssh-keygen -t ed25519` into tmpfs: its OpenSSH encoding is what ssh reads. `(pub, private)`.
pub fn generate_with_ssh_keygen() -> Result<(String, String), String> {
    let base = if std::path::Path::new("/dev/shm").is_dir() {
        PathBuf::from("/dev/shm")
    } else {
        std::env::temp_dir()
    };
    let dir = base.join(format!("cc-doctor-key-{}", hex::encode(rand::random::<[u8; 6]>())));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|_| "the Doctor key could not be made".to_string())?;
    }
    let path = dir.join("key");
    let made = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "ccdoctor", "-f"])
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let out = match made {
        Ok(s) if s.success() => {
            let p = std::fs::read_to_string(path.with_extension("pub")).map(|s| s.trim().to_string());
            let k = std::fs::read_to_string(&path);
            p.and_then(|p| k.map(|k| (p, k)))
                .map_err(|_| "the Doctor key could not be read".to_string())
        }
        _ => Err("the Doctor key could not be made".into()),
    };
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// `crypto.sign(null, message, vm_private_key.pem)`: the firewall's ed25519 signature, base64.
pub fn sign_detached(keys: &cc_auth::keys::KeysDir, message: &str) -> Result<String, String> {
    use ed25519_dalek::Signer;
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let pem = keys.read("vm_private_key.pem").ok_or("no signing key")?;
    let key =
        ed25519_dalek::SigningKey::from_pkcs8_pem(&pem).map_err(|_| "the signing key does not read".to_string())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key.sign(message.as_bytes()).to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{AgentClient, AgentError};
    use cc_http::BoxFuture;
    use serde_json::Map;

    struct Agent(Mutex<Vec<String>>);
    impl AgentClient for Agent {
        fn post(&self, vm: &str, path: &str, body: Value) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
            self.0.lock().expect("lock").push(format!("{vm} {path}"));
            let fp = fingerprint(body["pub"].as_str().unwrap_or(""));
            Box::pin(async move { Ok(crate::integrations::as_map(json!({"fingerprint": fp}))) })
        }
        fn get(&self, vm: &str, _: &str) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
            let down = vm == "vm-down";
            Box::pin(async move {
                if down {
                    return Err(AgentError {
                        message: "connect failed".into(),
                        timed_out: false,
                    });
                }
                Ok(crate::integrations::as_map(
                    json!({"fingerprint": "old", "sshHostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA host"}),
                ))
            })
        }
    }

    #[tokio::test]
    async fn the_standing_key_is_sealed_never_rotates_and_reaches_every_agent() {
        let dir = tempfile::tempdir().expect("dir");
        let key = cc_crypto::secret_store::generate_box_key();
        let made = Arc::new(Mutex::new(0));
        let m = made.clone();
        let generate: Generate = Arc::new(move || {
            *m.lock().expect("lock") += 1;
            Ok((
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOk ccdoctor".into(),
                "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n".into(),
            ))
        });
        let sign: Sign = Arc::new(|m| Ok(format!("sig:{}", m.len())));
        let path = dir.path().join("doctor.enc");
        let s = DoctorKeyStore::open(path.clone(), &key, "org", "fw", sign.clone(), generate.clone()).expect("open");
        assert!(!std::fs::read_to_string(&path).expect("file").contains("secret"));
        let p = s.public_key();
        assert_eq!(p["fingerprint"], json!(fingerprint(p["pub"].as_str().expect("pub"))));
        assert_eq!(
            p["sig"],
            json!(format!(
                "sig:{}",
                DOCTOR_KEY_DOMAIN.len() + p["pub"].as_str().expect("pub").len()
            ))
        );
        let client: Arc<dyn AgentClient> = Arc::new(Agent(Mutex::new(vec![])));
        s.reconcile(&["vm-1".into(), "vm-down".into()], &client).await;
        assert!(s.ready("vm-1") && !s.ready("vm-down"));
        assert_eq!(
            s.host_key("vm-1").as_deref(),
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA host")
        );
        // A restart keeps the key and what the agents answered.
        let again =
            DoctorKeyStore::open(path.clone(), &key, "org", "fw", sign.clone(), generate.clone()).expect("open");
        assert_eq!(*made.lock().expect("lock"), 1);
        assert_eq!(
            (again.private_key(), again.ready_ids()),
            (s.private_key(), vec!["vm-1".to_string()])
        );
        // A store that will not open is never replaced by a fresh key.
        assert!(
            DoctorKeyStore::open(
                path,
                &cc_crypto::secret_store::generate_box_key(),
                "org",
                "fw",
                sign,
                generate
            )
            .is_err()
        );
        assert_eq!(*made.lock().expect("lock"), 1);
    }
}
