//! W3 owns this file: the recovery identity (signing key from the recovery secret), the LUKS
//! passphrase seal, the recovery-confirm challenge and the archive file container, ported from
//! `packages/backup-envelope/src/{recovery-identity,luks-recovery,recovery-confirm,archive-file}.ts`
//! with their tests and TS-sealed fixtures, as `envelope` was.
//!
//! Here: the disk passphrase seal, the recovery identity, request signatures, the recovery request body and the
//! archive file (below the challenge), and the recovery-confirm challenge (`recovery-confirm.ts`). When no channel can deliver
//! a confirmation code, the firewall seals a fresh answer to the organization's recovery wrap key
//! (X25519) instead, and keeps only its hash; the owner opens it with that key.
//!
//! ```text
//! answer    = 16 characters of a 32-letter alphabet (80 bits), fresh per proposal
//! plaintext = "controlclaw/recovery-confirm/v1\n" ‖ JSON { changeId, subject, summary, expiresAt, answer }
//! challenge = crypto_box_seal(plaintext, recoveryPublicKey)
//! ```
//!
//! The wrap key also opens backups, so the opener is strict: it returns the answer only from a
//! plaintext with this context line that parses as exactly this JSON for the change asked about.

use crate::{CryptoError, Result, b64};
use dryoc::classic::crypto_box::{PublicKey, SecretKey, crypto_box_seal, crypto_box_seal_open};
use dryoc::classic::crypto_core::crypto_scalarmult_base;
use dryoc::classic::crypto_generichash::{
    GenericHashState, crypto_generichash, crypto_generichash_final, crypto_generichash_init, crypto_generichash_update,
};
use dryoc::classic::crypto_sign::{crypto_sign_detached, crypto_sign_seed_keypair, crypto_sign_verify_detached};
use dryoc::constants::CRYPTO_BOX_SEALBYTES;
use rand::Rng;
use serde_json::{Map, Value};

/// Domain separation for what is sealed. Changing it invalidates every open challenge.
pub const RECOVERY_CONFIRM_CONTEXT: &str = "controlclaw/recovery-confirm/v1";
/// Crockford base32, lower case: no i, l, o or u.
const ALPHABET: &str = "0123456789abcdefghjkmnpqrstvwxyz";
pub const RECOVERY_ANSWER_LENGTH: usize = 16;

/// What a challenge says, for the page to show before the answer goes anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryChallengeBody {
    pub change_id: String,
    /// What is being changed, as the code message names it.
    pub subject: String,
    /// The firewall's own words for the change.
    pub summary: String,
    /// ISO time the firewall stops accepting the answer.
    pub expires_at: String,
    pub answer: String,
}

/// `makeRecoveryAnswer`: 80 bits in the alphabet above.
pub fn make_recovery_answer() -> String {
    let letters: Vec<char> = ALPHABET.chars().collect();
    let mut rng = rand::thread_rng();
    (0..RECOVERY_ANSWER_LENGTH)
        .map(|_| letters[rng.gen_range(0..letters.len())])
        .collect()
}

fn body_json(body: &RecoveryChallengeBody) -> String {
    let mut m = Map::new();
    m.insert("changeId".into(), Value::String(body.change_id.clone()));
    m.insert("subject".into(), Value::String(body.subject.clone()));
    m.insert("summary".into(), Value::String(body.summary.clone()));
    m.insert("expiresAt".into(), Value::String(body.expires_at.clone()));
    m.insert("answer".into(), Value::String(body.answer.clone()));
    Value::Object(m).to_string()
}

/// `sealRecoveryChallenge`: the firewall's half.
pub fn seal_recovery_challenge(body: &RecoveryChallengeBody, recovery_public_key_b64: &str) -> Result<String> {
    let plain = format!("{RECOVERY_CONFIRM_CONTEXT}\n{}", body_json(body));
    let pk: PublicKey = b64::decode(recovery_public_key_b64)?
        .try_into()
        .map_err(|_| CryptoError::new("invalid public key length"))?;
    let mut out = vec![0u8; plain.len() + CRYPTO_BOX_SEALBYTES];
    crypto_box_seal(&mut out, plain.as_bytes(), &pk).map_err(|e| CryptoError::new(e.to_string()))?;
    Ok(b64::encode(out))
}

const NOT_OURS: &str = "That is not a confirmation from your firewall.";

fn field(o: &Map<String, Value>, k: &str) -> Option<String> {
    match o.get(k) {
        Some(Value::String(s)) if !s.is_empty() && s.encode_utf16().count() <= 2000 => Some(s.clone()),
        _ => None,
    }
}

/// `openRecoveryChallenge`: the owner's half (the browser, `npx @controlclaw/recover answer`).
pub fn open_recovery_challenge(
    challenge_b64: &str,
    recovery_secret_key_b64: &str,
    expect_change_id: Option<&str>,
) -> Result<RecoveryChallengeBody> {
    let wrong_key = || {
        CryptoError::new(
            "This recovery key cannot open this confirmation. Check it is your organization's current recovery key.",
        )
    };
    let sk: SecretKey = b64::decode(recovery_secret_key_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(wrong_key)?;
    let sealed = b64::decode(challenge_b64).map_err(|_| wrong_key())?;
    if sealed.len() < CRYPTO_BOX_SEALBYTES {
        return Err(wrong_key());
    }
    let mut pk = [0u8; 32];
    crypto_scalarmult_base(&mut pk, &sk);
    let mut opened = vec![0u8; sealed.len() - CRYPTO_BOX_SEALBYTES];
    crypto_box_seal_open(&mut opened, &sealed, &pk, &sk).map_err(|_| wrong_key())?;
    let plain = String::from_utf8(opened).unwrap_or_default();
    let prefix = format!("{RECOVERY_CONFIRM_CONTEXT}\n");
    let rest = plain.strip_prefix(&prefix).ok_or_else(|| CryptoError::new(NOT_OURS))?;
    let Ok(Value::Object(o)) = serde_json::from_str::<Value>(rest) else {
        return Err(CryptoError::new(NOT_OURS));
    };
    let body = (|| {
        Some(RecoveryChallengeBody {
            change_id: field(&o, "changeId")?,
            subject: field(&o, "subject")?,
            summary: field(&o, "summary")?,
            expires_at: field(&o, "expiresAt")?,
            answer: field(&o, "answer")?,
        })
    })()
    .ok_or_else(|| CryptoError::new(NOT_OURS))?;
    if body.answer.chars().count() != RECOVERY_ANSWER_LENGTH || body.answer.chars().any(|c| !ALPHABET.contains(c)) {
        return Err(CryptoError::new(NOT_OURS));
    }
    if let Some(want) = expect_change_id
        && body.change_id != want
    {
        return Err(CryptoError::new(
            "This confirmation is for a different change. Close this dialog and start again.",
        ));
    }
    Ok(body)
}

// ---- the recovery identity (`recovery-identity.ts`) ----
//
// The signing keypair is derived from the recovery secret, so the owner keeps one secret:
//
//   seed    = blake2b-256( "controlclaw-recovery-sign/v1" ‖ recoverySecretKey )
//   keypair = crypto_sign_seed_keypair(seed)
//
// The firewall holds only the two public halves, and prints `recovery_key_fingerprint` of them on
// its serial console for the owner to compare with what the recover CLI prints.

const SIGN_SEED_CONTEXT: &str = "controlclaw-recovery-sign/v1";
const REQUEST_CONTEXT: &str = "controlclaw-recovery-request/v1";
const PAIR_CONTEXT: &str = "controlclaw-recovery-pair/v1";

/// How far a signed request's timestamp may be from the firewall's clock, either way.
pub const RECOVERY_REPLAY_WINDOW_MS: u64 = 5 * 60_000;

fn blake2b_32(input: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    crypto_generichash(&mut h, input, None).expect("32 bytes is a valid generichash length");
    h
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex in groups of four, joined by `-`.
fn grouped(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// `deriveRecoverySigningKeypair`: `(publicKey, secretKey)` in base64 (32 and 64 bytes).
pub fn derive_recovery_signing_keypair(recovery_secret_key_b64: &str) -> Result<(String, String)> {
    let secret = b64::decode(recovery_secret_key_b64)?;
    if secret.len() != 32 {
        return Err(CryptoError::new("That is not a recovery key."));
    }
    let mut input = SIGN_SEED_CONTEXT.as_bytes().to_vec();
    input.extend_from_slice(&secret);
    let (pk, sk) = crypto_sign_seed_keypair(&blake2b_32(&input));
    Ok((b64::encode(pk), b64::encode(sk)))
}

/// `recoveryPublicKeys`: `(publicKey, signingPublicKey)`.
pub fn recovery_public_keys(recovery_secret_key_b64: &str) -> Result<(String, String)> {
    let secret: SecretKey = b64::decode(recovery_secret_key_b64)?
        .try_into()
        .map_err(|_| CryptoError::new("That is not a recovery key."))?;
    let mut pk: PublicKey = [0u8; 32];
    crypto_scalarmult_base(&mut pk, &secret);
    Ok((
        b64::encode(pk),
        derive_recovery_signing_keypair(recovery_secret_key_b64)?.0,
    ))
}

/// `recoveryKeyFingerprint`: over both public halves, so a swapped signing key changes it.
pub fn recovery_key_fingerprint(public_key: &str, signing_public_key: &str) -> String {
    let h = blake2b_32(format!("{PAIR_CONTEXT}\n{public_key}\n{signing_public_key}").as_bytes());
    grouped(&hex(&h[..8]))
}

/// `recoveryBodyDigest`.
pub fn recovery_body_digest(body: &[u8]) -> String {
    hex(&blake2b_32(body))
}

/// `createRecoveryBodyHasher`: the same digest, fed in pieces.
pub struct RecoveryBodyHasher(GenericHashState);

impl Default for RecoveryBodyHasher {
    fn default() -> Self {
        Self(crypto_generichash_init(None, 32).expect("32 bytes is a valid generichash length"))
    }
}

impl RecoveryBodyHasher {
    pub fn update(&mut self, chunk: &[u8]) {
        crypto_generichash_update(&mut self.0, chunk);
    }
    pub fn digest(self) -> String {
        let mut h = [0u8; 32];
        crypto_generichash_final(self.0, &mut h).expect("32 bytes is a valid generichash length");
        hex(&h)
    }
}

fn signed_string(method: &str, path: &str, timestamp: f64, digest: &str) -> String {
    // `${timestamp}`: what JS prints for a number.
    let ts = if timestamp.fract() == 0.0 && timestamp.abs() < 1e21 {
        format!("{}", timestamp as i64)
    } else {
        format!("{timestamp}")
    };
    format!("{REQUEST_CONTEXT}\n{}\n{path}\n{ts}\n{digest}", method.to_uppercase())
}

/// `signRecoveryRequest`, over a body digest.
pub fn sign_recovery_request(
    signing_secret_key_b64: &str,
    method: &str,
    path: &str,
    timestamp: f64,
    digest: &str,
) -> Result<String> {
    let sk: [u8; 64] = b64::decode(signing_secret_key_b64)?
        .try_into()
        .map_err(|_| CryptoError::new("not a signing key"))?;
    let mut sig = [0u8; 64];
    crypto_sign_detached(&mut sig, signed_string(method, path, timestamp, digest).as_bytes(), &sk)
        .map_err(|e| CryptoError::new(e.to_string()))?;
    Ok(b64::encode(sig))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryVerdict {
    Ok,
    /// The clock is out: worth saying, and not counted against the lockout.
    Stale(String),
    BadSignature(String),
}

/// What a recovery signature covers, besides the key and the signature.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryRequest<'a> {
    pub method: &'a str,
    /// The path only, no query.
    pub path: &'a str,
    /// Milliseconds since the epoch, as the caller's clock has it.
    pub timestamp: f64,
    /// `recovery_body_digest` of the whole body.
    pub digest: &'a str,
}

/// `verifyRecoveryRequest`.
pub fn verify_recovery_request(
    signing_public_key_b64: &str,
    signature_b64: &str,
    r: RecoveryRequest<'_>,
    now: f64,
    window_ms: u64,
) -> RecoveryVerdict {
    let RecoveryRequest {
        method,
        path,
        timestamp,
        digest,
    } = r;
    let window = window_ms as f64;
    if !timestamp.is_finite() || (now - timestamp).abs() > window {
        return RecoveryVerdict::Stale(format!(
            "This request is dated {}s away from the firewall's clock, and the window is {}s. Check the clock on the machine you are running this from.",
            js_round((now - timestamp).abs() / 1000.0),
            js_round(window / 1000.0)
        ));
    }
    let good = (|| {
        let sig: [u8; 64] = b64::decode(signature_b64).ok()?.try_into().ok()?;
        let pk: [u8; 32] = b64::decode(signing_public_key_b64).ok()?.try_into().ok()?;
        crypto_sign_verify_detached(&sig, signed_string(method, path, timestamp, digest).as_bytes(), &pk).ok()
    })()
    .is_some();
    if good {
        RecoveryVerdict::Ok
    } else {
        RecoveryVerdict::BadSignature("This request is not signed by the recovery key this firewall was given.".into())
    }
}

/// `Math.round` as text: `NaN` and `Infinity` as JS prints them.
fn js_round(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        "Infinity".into()
    } else {
        format!("{}", (v + 0.5).floor() as i64)
    }
}

// ---- the wire between the CLI and the firewall ----

/// `"CCRCV001"`, a u32 BE length, the JSON head, then the archive or nothing.
pub const RECOVERY_BODY_MAGIC: &str = "CCRCV001";
const RECOVERY_BODY_HEADER_BYTES: usize = 12;
const MAX_RECOVERY_HEAD_BYTES: usize = 64 * 1024;
pub const NOT_A_RECOVERY_REQUEST: &str = "This is not a recovery request.";

/// `encodeRecoveryBody`.
pub fn encode_recovery_body(head: &Value, tail: &[u8]) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(head).map_err(|e| CryptoError::new(e.to_string()))?;
    if body.len() > MAX_RECOVERY_HEAD_BYTES {
        return Err(CryptoError::new(
            "This request's head is larger than the recovery protocol allows.",
        ));
    }
    let mut out = Vec::with_capacity(RECOVERY_BODY_HEADER_BYTES + body.len() + tail.len());
    out.extend_from_slice(RECOVERY_BODY_MAGIC.as_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(tail);
    Ok(out)
}

/// `decodeRecoveryBody`: the head and the offset the tail starts at.
pub fn decode_recovery_body(bytes: &[u8]) -> Result<(Map<String, Value>, usize)> {
    if bytes.len() < RECOVERY_BODY_HEADER_BYTES {
        return Err(CryptoError::new("This request is too short to be a recovery request."));
    }
    if &bytes[..8] != RECOVERY_BODY_MAGIC.as_bytes() {
        return Err(CryptoError::new(NOT_A_RECOVERY_REQUEST));
    }
    let len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    if len == 0 || len > MAX_RECOVERY_HEAD_BYTES || bytes.len() < RECOVERY_BODY_HEADER_BYTES + len {
        return Err(CryptoError::new("This recovery request's head is the wrong size."));
    }
    let end = RECOVERY_BODY_HEADER_BYTES + len;
    let unreadable = || CryptoError::new("This recovery request's head is not readable.");
    // `JSON.parse` of the UTF-8 text, lossy as `TextDecoder` is.
    let text = String::from_utf8_lossy(&bytes[RECOVERY_BODY_HEADER_BYTES..end]);
    match serde_json::from_str::<Value>(&text).map_err(|_| unreadable())? {
        Value::Object(head) => Ok((head, end)),
        // `typeof head === "object"` holds for an array too; its fields then read as absent.
        Value::Array(_) => Ok((Map::new(), end)),
        _ => Err(unreadable()),
    }
}

// ---- the archive file (`archive-file.ts`) ----

/// `"CCBKUP01"`, a u32 BE length, the prelude JSON, then the sealed stream as it is.
pub const ARCHIVE_FILE_MAGIC: &str = "CCBKUP01";
pub const ARCHIVE_FILE_EXTENSION: &str = ".ccbak";
pub const ARCHIVE_FILE_HEADER_BYTES: usize = 12;
const MAX_PRELUDE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveKeyWrap {
    /// `firewall` or `recovery`.
    pub recipient: String,
    pub fingerprint: String,
    pub wrapped: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArchivePrelude {
    pub kind: String,
    pub backup_id: String,
    pub org_id: String,
    /// The box the archive was taken on: the `vmId` of the envelope binding.
    pub source_box_id: String,
    pub agent_name: String,
    pub taken_at: String,
    pub header: String,
    pub manifest_hash: String,
    pub wraps: Vec<ArchiveKeyWrap>,
    pub plain_bytes: f64,
    pub cipher_bytes: f64,
    pub entries: f64,
}

/// A JSON number as JS writes it: whole numbers without a fraction.
fn js_num(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 9_007_199_254_740_992.0 {
        Value::from(v as i64)
    } else {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

/// `parseArchivePrelude`.
pub fn parse_archive_prelude(json: &str) -> Result<ArchivePrelude> {
    let raw: Map<String, Value> = match serde_json::from_str::<Value>(json) {
        Ok(Value::Object(m)) => m,
        Ok(Value::Array(_)) => Map::new(),
        _ => {
            return Err(CryptoError::new(
                "This file's header is not readable, so it is not a ControlClaw backup.",
            ));
        }
    };
    let need = |k: &str| -> Result<String> {
        match raw.get(k) {
            Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
            _ => Err(CryptoError::new(format!(
                "This file's header has no {k}, so it cannot be opened."
            ))),
        }
    };
    if raw.get("version").and_then(Value::as_f64) != Some(1.0) {
        let v = match raw.get("version") {
            None => "undefined".to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
        };
        return Err(CryptoError::new(format!(
            "This file was written by a newer version of ControlClaw (format {v}). Update the recover tool."
        )));
    }
    let kind = need("kind")?;
    if !["workspace", "state", "firewall"].contains(&kind.as_str()) {
        return Err(CryptoError::new(format!(
            "This file says it is a {kind} archive, which this version does not know."
        )));
    }
    let wraps: Vec<ArchiveKeyWrap> = raw
        .get("wraps")
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter_map(|w| {
                    let o = w.as_object()?;
                    let recipient = o
                        .get("recipient")?
                        .as_str()
                        .filter(|r| *r == "firewall" || *r == "recovery")?;
                    Some(ArchiveKeyWrap {
                        recipient: recipient.into(),
                        fingerprint: o.get("fingerprint")?.as_str()?.into(),
                        wrapped: o.get("wrapped")?.as_str()?.into(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if wraps.is_empty() {
        return Err(CryptoError::new(
            "This file carries no sealed key, so nothing can open it.",
        ));
    }
    let num = |k: &str| raw.get(k).and_then(Value::as_f64).unwrap_or(0.0);
    let text = |k: &str| raw.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    Ok(ArchivePrelude {
        kind,
        backup_id: need("backupId")?,
        org_id: need("orgId")?,
        source_box_id: need("sourceBoxId")?,
        agent_name: text("agentName"),
        taken_at: text("takenAt"),
        header: need("header")?,
        manifest_hash: need("manifestHash")?,
        wraps,
        plain_bytes: num("plainBytes"),
        cipher_bytes: num("cipherBytes"),
        entries: num("entries"),
    })
}

fn prelude_json(p: &ArchivePrelude) -> Vec<u8> {
    let wraps: Vec<Value> = p
        .wraps
        .iter()
        .map(|w| serde_json::json!({"fingerprint": w.fingerprint, "recipient": w.recipient, "wrapped": w.wrapped}))
        .collect();
    let mut m = Map::new();
    m.insert("agentName".into(), Value::from(p.agent_name.clone()));
    m.insert("backupId".into(), Value::from(p.backup_id.clone()));
    m.insert("cipherBytes".into(), js_num(p.cipher_bytes));
    m.insert("entries".into(), js_num(p.entries));
    m.insert("envelope".into(), Value::from(1));
    m.insert("header".into(), Value::from(p.header.clone()));
    m.insert("kind".into(), Value::from(p.kind.clone()));
    m.insert("manifestHash".into(), Value::from(p.manifest_hash.clone()));
    m.insert("orgId".into(), Value::from(p.org_id.clone()));
    m.insert("plainBytes".into(), js_num(p.plain_bytes));
    m.insert("sourceBoxId".into(), Value::from(p.source_box_id.clone()));
    m.insert("takenAt".into(), Value::from(p.taken_at.clone()));
    m.insert("version".into(), Value::from(1));
    m.insert("wraps".into(), Value::Array(wraps));
    serde_json::to_vec(&Value::Object(m)).expect("a JSON value always serializes")
}

/// `encodeArchivePrelude`: canonical bytes, sorted keys.
pub fn encode_archive_prelude(p: &ArchivePrelude) -> Result<Vec<u8>> {
    let body = prelude_json(p);
    if body.len() > MAX_PRELUDE_BYTES {
        return Err(CryptoError::new(
            "This backup's key material is larger than the archive format allows.",
        ));
    }
    let mut out = Vec::with_capacity(ARCHIVE_FILE_HEADER_BYTES + body.len());
    out.extend_from_slice(ARCHIVE_FILE_MAGIC.as_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq)]
pub enum ArchiveFileHead {
    Prelude {
        prelude: Box<ArchivePrelude>,
        stream_offset: usize,
    },
    /// No magic: an archive downloaded before the format existed, or a raw object.
    Raw,
    /// The magic is there but the prelude has not all arrived yet.
    Incomplete { need: usize },
}

/// `readArchiveFileHead`.
pub fn read_archive_file_head(bytes: &[u8]) -> Result<ArchiveFileHead> {
    let magic = ARCHIVE_FILE_MAGIC.as_bytes();
    let cmp = bytes.len().min(magic.len());
    if bytes[..cmp] != magic[..cmp] {
        return Ok(ArchiveFileHead::Raw);
    }
    if bytes.len() < ARCHIVE_FILE_HEADER_BYTES {
        return Ok(ArchiveFileHead::Incomplete {
            need: ARCHIVE_FILE_HEADER_BYTES - bytes.len(),
        });
    }
    let len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    if len == 0 || len > MAX_PRELUDE_BYTES {
        return Err(CryptoError::new(
            "This file's header is the wrong size, so it is not a ControlClaw backup.",
        ));
    }
    let end = ARCHIVE_FILE_HEADER_BYTES + len;
    if bytes.len() < end {
        return Ok(ArchiveFileHead::Incomplete {
            need: end - bytes.len(),
        });
    }
    let json = String::from_utf8_lossy(&bytes[ARCHIVE_FILE_HEADER_BYTES..end]);
    Ok(ArchiveFileHead::Prelude {
        prelude: Box::new(parse_archive_prelude(&json)?),
        stream_offset: end,
    })
}

/// `archiveFileId`: 6 bytes of BLAKE2b over the canonical prelude, in groups of four.
pub fn archive_file_id(p: &ArchivePrelude) -> String {
    grouped(&hex(&blake2b_32(&prelude_json(p))[..6]))
}

// ---- the disk passphrase seal (`luks-recovery.ts`) ----
//
// A box seals its LUKS passphrase to the recovery key with primitives Node ships with (it runs
// before any package is installed), so this is not `crypto_box_seal`:
//
//   eph    = X25519 keypair, per seal
//   shared = X25519(eph.secret, recoveryPublicKey)
//   key    = HKDF-SHA256(shared, salt = eph.public ‖ recoveryPublicKey, info = CONTEXT, 32)
//   blob   = { v: 1, eph, iv, ct }   AES-256-GCM, tag appended to ct
//
// The box's copy is `cc-seal` in the Ansible role; `LUKS_SEAL_VECTOR` in the TS pins both.

/// Domain separation. Changing it invalidates every sealed passphrase.
pub const LUKS_SEAL_CONTEXT: &str = "controlclaw/luks-recovery/v1";

/// `recoveryKeyTag`: "sha256:" and the first 8 bytes of SHA-256 over the raw public key.
pub fn recovery_key_tag(public_key_b64: &str) -> String {
    use sha2::Digest;
    let raw = b64::decode(public_key_b64).unwrap_or_default();
    let d = sha2::Sha256::digest(raw);
    format!("sha256:{}", hex(&d[..8]))
}

/// `sealedTo`: the tag a blob carries, when it has a well-formed one.
pub fn sealed_to(blob: &Value) -> Option<String> {
    let to = blob.get("to")?.as_str()?;
    let ok = to.len() == 23
        && to.starts_with("sha256:")
        && to[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    ok.then(|| to.to_string())
}

/// `sealedToAnotherKey`: both tags when the blob names a different key from this secret's.
pub fn sealed_to_another_key(blob: &Value, recovery_secret_key_b64: &str) -> Option<(String, String)> {
    let named = sealed_to(blob)?;
    let (pk, _) = recovery_public_keys(recovery_secret_key_b64).ok()?;
    let key = recovery_key_tag(&pk);
    (key != named).then_some((named, key))
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha2::Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = sha2::Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = sha2::Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// HKDF-SHA256 with a 32-byte output: one expand block.
fn hkdf_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(salt, &[ikm]);
    hmac_sha256(&prk, &[info, &[1u8]])
}

fn luks_key(shared: &[u8; 32], eph_public: &[u8], recipient: &[u8]) -> [u8; 32] {
    let mut salt = eph_public.to_vec();
    salt.extend_from_slice(recipient);
    hkdf_32(shared, &salt, LUKS_SEAL_CONTEXT.as_bytes())
}

/// `openSealedPassphrase`: with the owner's recovery secret.
pub fn open_sealed_passphrase(blob: &Value, recovery_secret_key_b64: &str) -> Result<String> {
    use aes_gcm::aead::{Aead, KeyInit};
    if blob.get("v").and_then(Value::as_f64) != Some(1.0) {
        return Err(CryptoError::new("Unknown sealed-passphrase version."));
    }
    let secret: [u8; 32] = b64::decode(recovery_secret_key_b64)?
        .try_into()
        .map_err(|_| CryptoError::new("That is not a recovery key."))?;
    let field = |k: &str| b64::decode(blob.get(k).and_then(Value::as_str).unwrap_or_default());
    let eph: [u8; 32] = field("eph")?
        .try_into()
        .map_err(|_| CryptoError::new("Malformed sealed passphrase."))?;
    let mut shared = [0u8; 32];
    dryoc::classic::crypto_core::crypto_scalarmult(&mut shared, &secret, &eph);
    let mut recipient = [0u8; 32];
    crypto_scalarmult_base(&mut recipient, &secret);
    let key = luks_key(&shared, &eph, &recipient);
    let wrong = || CryptoError::new("That recovery key does not open this box's disk.");
    let iv = field("iv")?;
    if iv.len() != 12 {
        return Err(wrong());
    }
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(|_| wrong())?;
    let plain = cipher
        .decrypt(aes_gcm::Nonce::from_slice(&iv), field("ct")?.as_slice())
        .map_err(|_| wrong())?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

/// `sealPassphrase`: the box does this with `cc-seal`; here for the round trip and the tests.
pub fn seal_passphrase(passphrase: &str, recovery_public_key_b64: &str) -> Result<Value> {
    use aes_gcm::aead::{Aead, KeyInit};
    let recipient: [u8; 32] = b64::decode(recovery_public_key_b64)?
        .try_into()
        .map_err(|_| CryptoError::new("That is not a recovery public key."))?;
    let mut eph_secret = [0u8; 32];
    rand::thread_rng().fill(&mut eph_secret);
    let mut eph_public = [0u8; 32];
    crypto_scalarmult_base(&mut eph_public, &eph_secret);
    let mut shared = [0u8; 32];
    dryoc::classic::crypto_core::crypto_scalarmult(&mut shared, &eph_secret, &recipient);
    let key = luks_key(&shared, &eph_public, &recipient);
    let mut iv = [0u8; 12];
    rand::thread_rng().fill(&mut iv);
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(|e| CryptoError::new(e.to_string()))?;
    let ct = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&iv), passphrase.as_bytes())
        .map_err(|e| CryptoError::new(e.to_string()))?;
    Ok(serde_json::json!({"v": 1, "eph": b64::encode(eph_public), "iv": b64::encode(iv), "ct": b64::encode(ct)}))
}

#[cfg(test)]
mod luks_tests {
    use super::*;
    use serde_json::json;

    // `LUKS_SEAL_VECTOR` in packages/backup-envelope.
    const SECRET: &str = "Y29udHJvbGNsYXctbHVrcy1zZWFsLXRlc3QtdmVjdG8=";
    const PUBLIC: &str = "OLIAAYYu9C/XU5mQckoX00FBWNlYg7+Ur4qx2M/tKXs=";

    #[test]
    fn opens_the_ts_vector_and_cc_seal() {
        assert_eq!(recovery_key_tag(PUBLIC), "sha256:0006bb1c1b76749b");
        let sealed = json!({"v": 1, "eph": "DNeI9JVpucy5zvkkwMUvGGkdlEB73HMIMluNnjz8sHk=", "iv": "Yr0Nnhumk9xZOHUT", "ct": "P0RioW2uVExRNeuGbesfn/f7EpXKmbx23w+85AUJ+CERJSET0K3JEdj4qng="});
        assert_eq!(
            open_sealed_passphrase(&sealed, SECRET).expect("open"),
            "vector-passphrase-do-not-use"
        );
        let by_cc_seal = json!({"v": 1, "eph": "+t4Da1Qc+E1eqUeV52CkH+joWZecDenaIzI0RfA9RC4=", "iv": "qPRNfpnF5Cd8tuqB", "ct": "x3mhV1GNdprHIFuzUqZvVpYxLQvN+CGGP98WHCTGMuopBzUH3o9q3WpNeasznCjs"});
        assert_eq!(
            open_sealed_passphrase(&by_cc_seal, SECRET).expect("open"),
            "a-real-looking-passphrase-abc123"
        );
        let mine = seal_passphrase("round trip", PUBLIC).expect("seal");
        assert_eq!(open_sealed_passphrase(&mine, SECRET).expect("open"), "round trip");
        let other = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        assert_eq!(
            open_sealed_passphrase(&mine, other).expect_err("wrong").0,
            "That recovery key does not open this box's disk."
        );
        let tagged = json!({"v": 1, "to": "sha256:0006bb1c1b76749b"});
        assert_eq!(sealed_to(&tagged).as_deref(), Some("sha256:0006bb1c1b76749b"));
        assert_eq!(sealed_to_another_key(&tagged, SECRET), None);
        assert!(sealed_to_another_key(&tagged, other).is_some());
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    // From packages/backup-envelope (libsodium), secret = 32 bytes of 7.
    const SECRET: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    const SIGN_PUB: &str = "zTYmVgDEldv5RDSH7wCFeUVqh12d3w7mdGKXTFsd1CA=";
    const SIGN_SECRET: &str =
        "/WS9zNOqMYoUl1ZNWy+FBGpixVJhfzx0+QapjLrbT2fNNiZWAMSV2/lENIfvAIV5RWqHXZ3fDuZ0YpdMWx3UIA==";
    const WRAP_PUB: &str = "E75P6uryBMf9M1j8nAByGIHRdCeBKCJ+xnTzf3/pe20=";
    const BODY: &str = "Q0NSQ1YwMDEAAAAheyJiYWNrdXBJZCI6ImIxIiwiYWdlbnQiOiJhdGxhcyJ9AQID";
    const DIGEST: &str = "af0188c7531d350e1e9824f5e7bc1b55488ba95b411f2e0708f6e56b982ac3e1";
    const SIG: &str = "r0mmAumlMqYpHSMuzsLws1GXCD/gZlsaA99mGzJDWWyhBTzI1gBziePmO4M2yszowfISGYWbvckmI/Q0Ur9DDQ==";
    const TS: f64 = 1_700_000_000_000.0;

    #[test]
    fn identity_matches_libsodium() {
        assert_eq!(
            derive_recovery_signing_keypair(SECRET).expect("kp"),
            (SIGN_PUB.into(), SIGN_SECRET.into())
        );
        assert_eq!(
            recovery_public_keys(SECRET).expect("pk"),
            (WRAP_PUB.into(), SIGN_PUB.into())
        );
        assert_eq!(recovery_key_fingerprint(WRAP_PUB, SIGN_PUB), "91b2-fcd4-f02f-29c4");
        assert!(derive_recovery_signing_keypair("AAAA").is_err());
    }

    #[test]
    fn signatures_match_and_verify() {
        let body = b64::decode(BODY).expect("b64");
        assert_eq!(recovery_body_digest(&body), DIGEST);
        let mut h = RecoveryBodyHasher::default();
        h.update(&body[..5]);
        h.update(&body[5..]);
        assert_eq!(h.digest(), DIGEST);
        assert_eq!(
            sign_recovery_request(SIGN_SECRET, "post", "/recovery/hello", TS, DIGEST).expect("sig"),
            SIG
        );
        let v = |sig: &str, path: &str, now: f64| {
            verify_recovery_request(
                SIGN_PUB,
                sig,
                RecoveryRequest {
                    method: "POST",
                    path,
                    timestamp: TS,
                    digest: DIGEST,
                },
                now,
                RECOVERY_REPLAY_WINDOW_MS,
            )
        };
        assert_eq!(v(SIG, "/recovery/hello", TS + 1000.0), RecoveryVerdict::Ok);
        assert!(matches!(
            v(SIG, "/recovery/agent-restore", TS),
            RecoveryVerdict::BadSignature(_)
        ));
        assert!(matches!(
            v("not base64!", "/recovery/hello", TS),
            RecoveryVerdict::BadSignature(_)
        ));
        assert_eq!(
            v(SIG, "/recovery/hello", TS + 301_000.0),
            RecoveryVerdict::Stale("This request is dated 301s away from the firewall's clock, and the window is 300s. Check the clock on the machine you are running this from.".into())
        );
    }

    #[test]
    fn body_framing() {
        let body = b64::decode(BODY).expect("b64");
        let head = serde_json::json!({"backupId": "b1", "agent": "atlas"});
        assert_eq!(encode_recovery_body(&head, &[1, 2, 3]).expect("enc"), body);
        let (h, at) = decode_recovery_body(&body).expect("dec");
        assert_eq!(Value::Object(h), head);
        assert_eq!(&body[at..], &[1, 2, 3]);
        assert_eq!(
            decode_recovery_body(b"XXXXXXXX0000").expect_err("magic").0,
            NOT_A_RECOVERY_REQUEST
        );
        assert_eq!(
            decode_recovery_body(&body[..20]).expect_err("short").0,
            "This recovery request's head is the wrong size."
        );
        assert_eq!(
            decode_recovery_body(b"CCRC").expect_err("tiny").0,
            "This request is too short to be a recovery request."
        );
    }

    #[test]
    fn archive_file_matches_ts() {
        let p = ArchivePrelude {
            kind: "workspace".into(),
            backup_id: "b1".into(),
            org_id: "org_1".into(),
            source_box_id: "vm_1".into(),
            agent_name: "atlas".into(),
            taken_at: "2026-10-01T00:00:00.000Z".into(),
            header: "aGVhZGVy".into(),
            manifest_hash: "ab".into(),
            wraps: vec![ArchiveKeyWrap {
                recipient: "recovery".into(),
                fingerprint: "aaaa-bbbb-cccc-dddd".into(),
                wrapped: "d3JhcA==".into(),
            }],
            plain_bytes: 10.0,
            cipher_bytes: 27.0,
            entries: 2.0,
        };
        let enc = encode_archive_prelude(&p).expect("enc");
        assert_eq!(
            b64::encode(&enc),
            "Q0NCS1VQMDEAAAFMeyJhZ2VudE5hbWUiOiJhdGxhcyIsImJhY2t1cElkIjoiYjEiLCJjaXBoZXJCeXRlcyI6MjcsImVudHJpZXMiOjIsImVudmVsb3BlIjoxLCJoZWFkZXIiOiJhR1ZoWkdWeSIsImtpbmQiOiJ3b3Jrc3BhY2UiLCJtYW5pZmVzdEhhc2giOiJhYiIsIm9yZ0lkIjoib3JnXzEiLCJwbGFpbkJ5dGVzIjoxMCwic291cmNlQm94SWQiOiJ2bV8xIiwidGFrZW5BdCI6IjIwMjYtMTAtMDFUMDA6MDA6MDAuMDAwWiIsInZlcnNpb24iOjEsIndyYXBzIjpbeyJmaW5nZXJwcmludCI6ImFhYWEtYmJiYi1jY2NjLWRkZGQiLCJyZWNpcGllbnQiOiJyZWNvdmVyeSIsIndyYXBwZWQiOiJkM0poY0E9PSJ9XX0="
        );
        assert_eq!(archive_file_id(&p), "ad69-7371-4e0f");
        let mut file = enc.clone();
        file.extend_from_slice(b"stream");
        assert_eq!(
            read_archive_file_head(&file).expect("head"),
            ArchiveFileHead::Prelude {
                prelude: Box::new(p),
                stream_offset: enc.len()
            }
        );
        assert_eq!(read_archive_file_head(b"raw bytes").expect("raw"), ArchiveFileHead::Raw);
        assert_eq!(
            read_archive_file_head(&enc[..20]).expect("inc"),
            ArchiveFileHead::Incomplete { need: enc.len() - 20 }
        );
        assert_eq!(
            parse_archive_prelude(r#"{"version":2}"#).expect_err("v").0,
            "This file was written by a newer version of ControlClaw (format 2). Update the recover tool."
        );
        assert_eq!(
            parse_archive_prelude(r#"{"version":1,"kind":"workspace","wraps":[]}"#)
                .expect_err("w")
                .0,
            "This file carries no sealed key, so nothing can open it."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{generate_recipient_keypair, wrap_data_key};

    fn body(answer: &str) -> RecoveryChallengeBody {
        RecoveryChallengeBody {
            change_id: "chg_1".into(),
            subject: "MJHBot".into(),
            summary: "Update the agent".into(),
            expires_at: "2026-10-28T10:00:00.000Z".into(),
            answer: answer.into(),
        }
    }

    #[test]
    fn answers_are_in_the_alphabet() {
        for _ in 0..50 {
            let a = make_recovery_answer();
            assert_eq!(a.len(), RECOVERY_ANSWER_LENGTH);
            assert!(a.chars().all(|c| ALPHABET.contains(c)));
        }
    }

    #[test]
    fn a_challenge_opens_with_its_key_only_for_its_change() {
        let k = generate_recipient_keypair();
        let other = generate_recipient_keypair();
        let answer = make_recovery_answer();
        let sealed = seal_recovery_challenge(&body(&answer), &k.public_key).expect("seal");
        let open = open_recovery_challenge(&sealed, &k.secret_key, Some("chg_1")).expect("open");
        assert_eq!(open, body(&answer));
        assert!(open_recovery_challenge(&sealed, &k.secret_key, None).is_ok());
        assert_eq!(
            open_recovery_challenge(&sealed, &k.secret_key, Some("chg_2"))
                .expect_err("other change")
                .0,
            "This confirmation is for a different change. Close this dialog and start again."
        );
        assert!(
            open_recovery_challenge(&sealed, &other.secret_key, None)
                .expect_err("other key")
                .0
                .starts_with("This recovery key cannot open")
        );
    }

    #[test]
    fn a_wrapped_data_key_or_a_bad_answer_is_not_a_confirmation() {
        let k = generate_recipient_keypair();
        let wrapped = wrap_data_key(&b64::encode([7u8; 32]), &k.public_key).expect("wrap");
        assert_eq!(
            open_recovery_challenge(&wrapped, &k.secret_key, None)
                .expect_err("data key")
                .0,
            NOT_OURS
        );
        let sealed = seal_recovery_challenge(&body("ILOU000000000000"), &k.public_key).expect("seal");
        assert_eq!(
            open_recovery_challenge(&sealed, &k.secret_key, None)
                .expect_err("letters")
                .0,
            NOT_OURS
        );
        let sealed = seal_recovery_challenge(&body("short"), &k.public_key).expect("seal");
        assert_eq!(
            open_recovery_challenge(&sealed, &k.secret_key, None)
                .expect_err("length")
                .0,
            NOT_OURS
        );
        let mut empty = body(&make_recovery_answer());
        empty.subject = String::new();
        let sealed = seal_recovery_challenge(&empty, &k.public_key).expect("seal");
        assert_eq!(
            open_recovery_challenge(&sealed, &k.secret_key, None)
                .expect_err("empty")
                .0,
            NOT_OURS
        );
    }

    #[test]
    fn the_plaintext_is_the_ts_layout() {
        assert_eq!(
            body_json(&body("abc")),
            r#"{"changeId":"chg_1","subject":"MJHBot","summary":"Update the agent","expiresAt":"2026-10-28T10:00:00.000Z","answer":"abc"}"#
        );
    }
}
