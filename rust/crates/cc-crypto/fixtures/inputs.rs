// The deterministic inputs of `fixtures/common.mts`, and how the Rust code opens and seals a
// fixtures file. `include!`d by the cross-check test and the `seal-fixtures` example.

use cc_crypto::envelope::{self, ArchiveKind, CHUNK_BYTES, Decryptor, Encryptor, EnvelopeBinding};
use cc_crypto::secret_store::{self, Ids, SealOpts, StoreRecord};
use cc_crypto::{b64, enc_file};
use serde::{Deserialize, Serialize};

const BOX_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const ENC_AAD: &str = "org_1:box_1:llm";
/// `JSON.stringify(ENC_VALUE)` as the TS writes it.
const ENC_VALUE_JSON: &str = r#"{"provider":"openai","apiKey":"sk-test-1234567890","nested":{"list":[1,2.5,null,true,"ü €"],"empty":{}},"quote\"key":"line\nbreak\u0001"}"#;
const STORE_PASSWORD: &str = "correct horse battery staple";
const STORE_PLAINTEXT: &str = r#"{"credentials":[{"match_domain":"github.com","secret":"ghp_x"}]}"#;
const STORE_VERSION: u64 = 7;
const STREAM_BYTES: usize = 600_000;

fn store_ids() -> Ids {
    Ids { org_id: "org_1".into(), box_id: "box_1".into() }
}
fn recipient_secret() -> String {
    b64::encode((0..32u32).map(|i| ((i * 7 + 3) & 0xff) as u8).collect::<Vec<_>>())
}
fn data_key() -> String {
    b64::encode((0..32u32).map(|i| ((255 - i) & 0xff) as u8).collect::<Vec<_>>())
}
fn binding() -> EnvelopeBinding {
    EnvelopeBinding { org_id: "org_1".into(), vm_id: "vm_1".into(), backup_id: "bk_1".into(), kind: ArchiveKind::Firewall }
}
fn stream_plain() -> Vec<u8> {
    (0..STREAM_BYTES as u32).map(|i| (i.wrapping_mul(31).wrapping_add(7) & 0xff) as u8).collect()
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipient {
    public_key: String,
    fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct Stream {
    header: String,
    blob: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixtures {
    sealed_by: String,
    enc_file: String,
    enc_value_json: String,
    store_record: StoreRecord,
    recipient: Recipient,
    wrapped: String,
    stream: Stream,
}

fn seal_with_rust() -> Fixtures {
    let value: serde_json::Value = serde_json::from_str(ENC_VALUE_JSON).expect("value");
    let public_key = envelope::public_key_of(&recipient_secret()).expect("public key");
    let mut enc = Encryptor::new(&data_key(), &binding()).expect("encryptor");
    let mut blob = Vec::new();
    for chunk in stream_plain().chunks(CHUNK_BYTES) {
        blob.extend(enc.push(chunk).expect("push"));
    }
    blob.extend(enc.finish().expect("final"));
    Fixtures {
        sealed_by: "rust".into(),
        enc_file: enc_file::encrypt_json(&value, BOX_KEY, ENC_AAD).expect("enc-file"),
        enc_value_json: serde_json::to_string(&value).expect("json"),
        store_record: secret_store::seal(
            STORE_PLAINTEXT,
            &SealOpts { box_key: BOX_KEY, master_password: STORE_PASSWORD, ids: &store_ids(), version: STORE_VERSION, salt: None },
        )
        .expect("store record"),
        recipient: Recipient { fingerprint: envelope::fingerprint(&public_key).expect("fingerprint"), public_key: public_key.clone() },
        wrapped: envelope::wrap_data_key(&data_key(), &public_key).expect("wrap"),
        stream: Stream { header: enc.header().to_string(), blob: b64::encode(blob) },
    }
}

/// Opens everything in `f` with the Rust code; returns the failures.
fn check_with_rust(f: &Fixtures) -> Vec<String> {
    let mut fails = Vec::new();
    let mut check = |name: &str, r: Result<bool, String>| match r {
        Ok(true) => {}
        Ok(false) => fails.push(name.to_string()),
        Err(e) => fails.push(format!("{name}: {e}")),
    };
    let expected: serde_json::Value = serde_json::from_str(ENC_VALUE_JSON).expect("value");
    check("enc-file opens to the same value", enc_file::decrypt_json(&f.enc_file, BOX_KEY, ENC_AAD).map(|v| v == expected).map_err(|e| e.0));
    check("serde_json writes the value as JSON.stringify does", Ok(serde_json::to_string(&expected).ok().as_deref() == Some(f.enc_value_json.as_str())));
    check("store record opens with the box key", secret_store::open_with_box_key(&f.store_record, BOX_KEY, &store_ids()).map(|p| p == STORE_PLAINTEXT).map_err(|e| e.0));
    check("store record opens with the password", secret_store::open_with_user_key(&f.store_record, STORE_PASSWORD, &store_ids()).map(|p| p == STORE_PLAINTEXT).map_err(|e| e.0));
    check("public key of the fixed secret", envelope::public_key_of(&recipient_secret()).map(|p| p == f.recipient.public_key).map_err(|e| e.0));
    check("fingerprint of the public key", envelope::fingerprint(&f.recipient.public_key).map(|p| p == f.recipient.fingerprint).map_err(|e| e.0));
    check("data key unwraps", envelope::unwrap_data_key(&f.wrapped, &recipient_secret()).map(|k| k == data_key()).map_err(|e| e.0));
    let opened = (|| -> Result<bool, String> {
        let mut dec = Decryptor::new(&data_key(), &f.stream.header, &binding()).map_err(|e| e.0)?;
        let blob = b64::decode(&f.stream.blob).map_err(|e| e.0)?;
        let mut out = Vec::new();
        for piece in blob.chunks(65_521) {
            for p in dec.push(piece).map_err(|e| e.0)? {
                out.extend(p);
            }
        }
        dec.end().map_err(|e| e.0)?;
        Ok(out == stream_plain())
    })();
    check("stream opens byte for byte", opened);
    fails
}
