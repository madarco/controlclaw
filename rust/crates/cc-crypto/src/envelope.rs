//! The backup envelope, port of `packages/backup-envelope/src/envelope.ts`.
//!
//! One random data key per backup encrypts the archive with libsodium's
//! `crypto_secretstream_xchacha20poly1305`, in 512 KiB chunks, each framed with a u32 big-endian
//! length. The data key is wrapped once per recipient with `crypto_box_seal`. Every chunk is bound
//! to `{orgId, vmId, backupId, kind}` as associated data. Bytes are the same as the TS (libsodium)
//! produces and reads: `dryoc` implements the same constructions.

use crate::{CryptoError, Result, b64};
use dryoc::classic::crypto_box::{PublicKey, SecretKey, crypto_box_keypair, crypto_box_seal, crypto_box_seal_open};
use dryoc::classic::crypto_core::crypto_scalarmult_base;
use dryoc::classic::crypto_generichash::crypto_generichash;
use dryoc::classic::crypto_secretstream_xchacha20poly1305 as ss;
use dryoc::constants::{
    CRYPTO_BOX_SEALBYTES, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
};
use rand::RngCore;

/// Which archive of a backup this is. They restore independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Workspace,
    State,
    Firewall,
    /// The organization's brain: its database dump, pages and settings.
    Gbrain,
}

impl ArchiveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ArchiveKind::Workspace => "workspace",
            ArchiveKind::State => "state",
            ArchiveKind::Firewall => "firewall",
            ArchiveKind::Gbrain => "gbrain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "workspace" => ArchiveKind::Workspace,
            "state" => ArchiveKind::State,
            "firewall" => ArchiveKind::Firewall,
            "gbrain" => ArchiveKind::Gbrain,
            _ => return None,
        })
    }
}

/// What a chunk is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeBinding {
    pub org_id: String,
    pub vm_id: String,
    pub backup_id: String,
    pub kind: ArchiveKind,
}

/// Plaintext bytes per chunk. 512 KiB keeps about 10k frames at the 5 GB limit.
pub const CHUNK_BYTES: usize = 512 * 1024;
/// Tag and MAC per chunk.
const STREAM_OVERHEAD: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
const FRAME_HEADER_BYTES: usize = 4;
const MAX_FRAME_BYTES: usize = CHUNK_BYTES + STREAM_OVERHEAD;
const KEY_BYTES: usize = CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES;

pub const WRONG_KEY: &str = "This archive could not be opened: the key or the backup it names is wrong.";
pub const TRUNCATED: &str = "This archive ended early — it is incomplete. Nothing was restored.";
pub const CANNOT_OPEN: &str = "This key cannot open that backup.";
const CLOSED: &str = "the archive stream is already closed";

/// The associated data. Field names are in it so no two bindings collide by shifting a value.
pub fn binding_aad(b: &EnvelopeBinding) -> String {
    format!(
        "controlclaw-backup/v1\norg={}\nvm={}\nbackup={}\nkind={}",
        b.org_id,
        b.vm_id,
        b.backup_id,
        b.kind.as_str()
    )
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn array<const N: usize>(bytes: &[u8], message: &str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| CryptoError::new(message))
}

// ---- keys ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeypair {
    /// base64 X25519 public key. The control plane may hold it.
    pub public_key: String,
    /// base64 X25519 secret key. Never leaves the firewall, or the owner's browser.
    pub secret_key: String,
    pub fingerprint: String,
}

pub fn generate_recipient_keypair() -> RecipientKeypair {
    let (pk, sk) = crypto_box_keypair();
    RecipientKeypair {
        public_key: b64::encode(pk),
        secret_key: b64::encode(sk),
        fingerprint: fingerprint_bytes(&pk),
    }
}

/// The public half of a secret key, so a saved recovery key is all anyone has to keep.
pub fn public_key_of(secret_key_b64: &str) -> Result<String> {
    let sk: SecretKey = array(&b64::decode(secret_key_b64)?, "invalid secret key length")?;
    let mut pk = [0u8; 32];
    crypto_scalarmult_base(&mut pk, &sk);
    Ok(b64::encode(pk))
}

/// A short name for a public key: BLAKE2b-256, first 8 bytes, hex, in groups of four.
pub fn fingerprint(public_key_b64: &str) -> Result<String> {
    Ok(fingerprint_bytes(&b64::decode(public_key_b64)?))
}

fn fingerprint_bytes(pk: &[u8]) -> String {
    let mut h = [0u8; 32];
    crypto_generichash(&mut h, pk, None).expect("32 bytes is a valid generichash length");
    let hex: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn random_data_key() -> String {
    let mut k = [0u8; KEY_BYTES];
    rand::thread_rng().fill_bytes(&mut k);
    b64::encode(k)
}

/// Wrap the data key for one recipient. Anonymous: the recipient learns nothing about the sender.
pub fn wrap_data_key(data_key_b64: &str, recipient_public_key_b64: &str) -> Result<String> {
    let msg = b64::decode(data_key_b64)?;
    let pk: PublicKey = array(&b64::decode(recipient_public_key_b64)?, "invalid public key length")?;
    let mut out = vec![0u8; msg.len() + CRYPTO_BOX_SEALBYTES];
    crypto_box_seal(&mut out, &msg, &pk).map_err(|e| CryptoError::new(e.to_string()))?;
    Ok(b64::encode(out))
}

/// Errors with [`CANNOT_OPEN`] for a wrap made for someone else, a tampered one, or malformed input.
pub fn unwrap_data_key(wrapped_b64: &str, secret_key_b64: &str) -> Result<String> {
    let cannot = || CryptoError::new(CANNOT_OPEN);
    let sk: SecretKey = b64::decode(secret_key_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(cannot)?;
    let wrapped = b64::decode(wrapped_b64).map_err(|_| cannot())?;
    if wrapped.len() < CRYPTO_BOX_SEALBYTES {
        return Err(cannot());
    }
    let mut pk = [0u8; 32];
    crypto_scalarmult_base(&mut pk, &sk);
    let mut open = vec![0u8; wrapped.len() - CRYPTO_BOX_SEALBYTES];
    crypto_box_seal_open(&mut open, &wrapped, &pk, &sk).map_err(|_| cannot())?;
    if open.len() != KEY_BYTES {
        return Err(cannot());
    }
    Ok(b64::encode(open))
}

/// Move a data key to a new recipient without touching the archive.
pub fn rewrap_data_key(wrapped: &str, secret_key: &str, to_public_key: &str) -> Result<String> {
    wrap_data_key(&unwrap_data_key(wrapped, secret_key)?, to_public_key)
}

// ---- the stream ----

pub struct Encryptor {
    state: ss::State,
    header: String,
    ad: Vec<u8>,
    closed: bool,
}

impl Encryptor {
    pub fn new(data_key_b64: &str, binding: &EnvelopeBinding) -> Result<Self> {
        let key: ss::Key = array(&b64::decode(data_key_b64)?, "invalid key length")?;
        let mut state = ss::State::new();
        let mut header = [0u8; CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES];
        ss::crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, &key);
        Ok(Self {
            state,
            header: b64::encode(header),
            ad: binding_aad(binding).into_bytes(),
            closed: false,
        })
    }

    /// base64 stream header (24 bytes). Kept in the `backup` row, not in the blob.
    pub fn header(&self) -> &str {
        &self.header
    }

    /// One framed ciphertext chunk. `plain` must be at most [`CHUNK_BYTES`].
    pub fn push(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        if self.closed {
            return Err(CryptoError::new(CLOSED));
        }
        if plain.len() > CHUNK_BYTES {
            return Err(CryptoError::new(format!(
                "chunk of {} bytes is over the {CHUNK_BYTES} limit",
                plain.len()
            )));
        }
        self.seal(plain, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE)
    }

    /// The FINAL-tagged empty chunk. Its absence is how a truncated archive is caught.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if self.closed {
            return Err(CryptoError::new(CLOSED));
        }
        self.closed = true;
        self.seal(&[], CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL)
    }

    fn seal(&mut self, plain: &[u8], tag: u8) -> Result<Vec<u8>> {
        let mut ct = vec![0u8; plain.len() + STREAM_OVERHEAD];
        ss::crypto_secretstream_xchacha20poly1305_push(&mut self.state, &mut ct, plain, Some(&self.ad), tag)
            .map_err(|e| CryptoError::new(e.to_string()))?;
        Ok(frame(&ct))
    }
}

pub struct Decryptor {
    state: ss::State,
    ad: Vec<u8>,
    buffer: Vec<u8>,
    saw_final: bool,
}

impl Decryptor {
    pub fn new(data_key_b64: &str, header_b64: &str, binding: &EnvelopeBinding) -> Result<Self> {
        let wrong = || CryptoError::new(WRONG_KEY);
        let header: ss::Header = b64::decode(header_b64)
            .ok()
            .and_then(|h| h.try_into().ok())
            .ok_or_else(wrong)?;
        let key: ss::Key = b64::decode(data_key_b64)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(wrong)?;
        let mut state = ss::State::new();
        ss::crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);
        Ok(Self {
            state,
            ad: binding_aad(binding).into_bytes(),
            buffer: Vec::new(),
            saw_final: false,
        })
    }

    /// Feed download pieces of any size; get back whatever plaintext is now complete.
    pub fn push(&mut self, cipher: &[u8]) -> Result<Vec<Vec<u8>>> {
        let wrong = || CryptoError::new(WRONG_KEY);
        self.buffer.extend_from_slice(cipher);
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let rest = &self.buffer[at..];
            if rest.len() < FRAME_HEADER_BYTES {
                break;
            }
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if !(STREAM_OVERHEAD..=MAX_FRAME_BYTES).contains(&len) {
                return Err(wrong());
            }
            if rest.len() < FRAME_HEADER_BYTES + len {
                break;
            }
            let body = &rest[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + len];
            at += FRAME_HEADER_BYTES + len;
            // A frame after the FINAL one means somebody appended to the blob: refuse it all.
            if self.saw_final {
                return Err(wrong());
            }
            let mut message = vec![0u8; len - STREAM_OVERHEAD];
            let mut tag = 0u8;
            ss::crypto_secretstream_xchacha20poly1305_pull(
                &mut self.state,
                &mut message,
                &mut tag,
                body,
                Some(&self.ad),
            )
            .map_err(|_| wrong())?;
            if tag == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL {
                self.saw_final = true;
            }
            if !message.is_empty() {
                out.push(message);
            }
        }
        self.buffer.drain(..at);
        Ok(out)
    }

    /// Errors with [`TRUNCATED`] unless the FINAL chunk arrived and nothing is left half-read.
    pub fn end(&self) -> Result<()> {
        if !self.saw_final || !self.buffer.is_empty() {
            return Err(CryptoError::new(TRUNCATED));
        }
        Ok(())
    }
}

/// How big the blob is for a plaintext size: the presigned PUT wants a bound.
pub fn cipher_size_for(plain_bytes: u64) -> u64 {
    let chunk = CHUNK_BYTES as u64;
    let frames = plain_bytes / chunk + u64::from(!plain_bytes.is_multiple_of(chunk)) + 1;
    plain_bytes + frames * (STREAM_OVERHEAD + FRAME_HEADER_BYTES) as u64
}

#[cfg(test)]
mod tests;
