//! The cases of `packages/backup-envelope/src/vectors.ts`.
#![allow(clippy::unwrap_used)]

use super::*;

fn binding() -> EnvelopeBinding {
    EnvelopeBinding {
        org_id: "org_1".into(),
        vm_id: "vm_1".into(),
        backup_id: "bk_1".into(),
        kind: ArchiveKind::Workspace,
    }
}

/// Sealed in 1024-byte pushes, as the TS vectors do.
fn sealed(key: &str, b: &EnvelopeBinding, plain: &[u8]) -> (String, Vec<u8>) {
    let mut enc = Encryptor::new(key, b).expect("encryptor");
    let mut blob = Vec::new();
    for piece in plain.chunks(1024) {
        blob.extend(enc.push(piece).expect("push"));
    }
    blob.extend(enc.finish().expect("final"));
    (enc.header().to_string(), blob)
}

/// Opened in deliberately ragged slices: a real download never hands over whole frames.
fn opened(key: &str, header: &str, b: &EnvelopeBinding, blob: &[u8]) -> Result<Vec<u8>> {
    let mut dec = Decryptor::new(key, header, b)?;
    let mut out = Vec::new();
    for piece in blob.chunks(7919) {
        for p in dec.push(piece)? {
            out.extend(p);
        }
    }
    dec.end()?;
    Ok(out)
}

#[test]
fn a_sealed_archive_round_trips_byte_for_byte() {
    let plain: Vec<u8> = (0..40_000u32).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
    let key = random_data_key();
    let (header, blob) = sealed(&key, &binding(), &plain);
    assert!(blob.len() > plain.len());
    assert!(!blob.windows(32).any(|w| w == &plain[8..40]));
    assert_eq!(opened(&key, &header, &binding(), &blob).expect("open"), plain);
}

#[test]
fn an_empty_archive_round_trips() {
    let key = random_data_key();
    let (header, blob) = sealed(&key, &binding(), &[]);
    assert!(opened(&key, &header, &binding(), &blob).expect("open").is_empty());
}

#[test]
fn a_blob_bound_to_another_backup_is_refused() {
    let key = random_data_key();
    let (header, blob) = sealed(&key, &binding(), &[1, 2, 3]);
    let b = binding();
    for wrong in [
        EnvelopeBinding {
            backup_id: "bk_2".into(),
            ..b.clone()
        },
        EnvelopeBinding {
            vm_id: "vm_2".into(),
            ..b.clone()
        },
        EnvelopeBinding {
            org_id: "org_2".into(),
            ..b.clone()
        },
        EnvelopeBinding {
            kind: ArchiveKind::State,
            ..b.clone()
        },
    ] {
        assert_eq!(opened(&key, &header, &wrong, &blob).unwrap_err().0, WRONG_KEY);
    }
}

#[test]
fn a_truncated_archive_is_refused() {
    let key = random_data_key();
    let (header, blob) = sealed(&key, &binding(), &[9u8; 9_000]);
    assert!(opened(&key, &header, &binding(), &blob[..blob.len() - 20]).is_err());
    assert!(opened(&key, &header, &binding(), &blob[..blob.len() - 1]).is_err());
    assert_eq!(opened(&key, &header, &binding(), &[]).unwrap_err().0, TRUNCATED);
    // Exactly on a frame boundary, where only the FINAL tag is missing: the dangerous one.
    assert_eq!(
        opened(&key, &header, &binding(), &blob[..blob.len() - 21])
            .unwrap_err()
            .0,
        TRUNCATED
    );
}

#[test]
fn bytes_appended_after_the_end_are_refused() {
    let key = random_data_key();
    let (header, blob) = sealed(&key, &binding(), &[4, 5, 6]);
    let doubled = [blob.clone(), blob].concat();
    assert!(opened(&key, &header, &binding(), &doubled).is_err());
}

#[test]
fn a_flipped_bit_anywhere_is_refused() {
    let key = random_data_key();
    let (header, blob) = sealed(&key, &binding(), &[2u8; 3_000]);
    for at in [4, 100, blob.len() - 5] {
        let mut t = blob.clone();
        t[at] ^= 1;
        assert!(opened(&key, &header, &binding(), &t).is_err(), "bit at {at}");
    }
}

#[test]
fn the_wrong_data_key_is_refused() {
    let key = random_data_key();
    let (header, blob) = sealed(&key, &binding(), &[7]);
    assert!(opened(&random_data_key(), &header, &binding(), &blob).is_err());
}

#[test]
fn each_recipient_can_unwrap_the_data_key_nobody_else_can() {
    let (firewall, recovery, stranger) = (
        generate_recipient_keypair(),
        generate_recipient_keypair(),
        generate_recipient_keypair(),
    );
    let key = random_data_key();
    let for_fw = wrap_data_key(&key, &firewall.public_key).expect("wrap");
    let for_rec = wrap_data_key(&key, &recovery.public_key).expect("wrap");
    assert_ne!(for_fw, for_rec);
    assert_eq!(unwrap_data_key(&for_fw, &firewall.secret_key).expect("fw"), key);
    assert_eq!(unwrap_data_key(&for_rec, &recovery.secret_key).expect("rec"), key);
    assert!(unwrap_data_key(&for_fw, &stranger.secret_key).is_err());
    assert!(unwrap_data_key(&for_fw, &recovery.secret_key).is_err());
}

#[test]
fn a_recovery_keys_public_half_is_derivable() {
    let kp = generate_recipient_keypair();
    assert_eq!(public_key_of(&kp.secret_key).expect("pub"), kp.public_key);
    assert_eq!(fingerprint(&kp.public_key).expect("fp"), kp.fingerprint);
}

#[test]
fn rewrapping_to_a_rebuilt_firewall_opens_the_same_archive() {
    let (old_fw, recovery) = (generate_recipient_keypair(), generate_recipient_keypair());
    let key = random_data_key();
    let plain = [3u8; 5_000];
    let (header, blob) = sealed(&key, &binding(), &plain);
    let wrap_fw = wrap_data_key(&key, &old_fw.public_key).expect("wrap");
    let wrap_rec = wrap_data_key(&key, &recovery.public_key).expect("wrap");
    let new_fw = generate_recipient_keypair();
    assert!(unwrap_data_key(&wrap_fw, &new_fw.secret_key).is_err());
    let rewrapped = rewrap_data_key(&wrap_rec, &recovery.secret_key, &new_fw.public_key).expect("rewrap");
    assert_ne!(rewrapped, wrap_rec);
    let k2 = unwrap_data_key(&rewrapped, &new_fw.secret_key).expect("unwrap");
    assert_eq!(k2, key);
    assert_eq!(
        opened(&k2, &header, &binding(), &blob).expect("open").len(),
        plain.len()
    );
}

#[test]
fn a_rewrap_with_the_wrong_recovery_key_fails() {
    let (recovery, wrong, target) = (
        generate_recipient_keypair(),
        generate_recipient_keypair(),
        generate_recipient_keypair(),
    );
    let wrapped = wrap_data_key(&random_data_key(), &recovery.public_key).expect("wrap");
    assert!(rewrap_data_key(&wrapped, &wrong.secret_key, &target.public_key).is_err());
}

#[test]
fn corrupt_input_reads_as_the_envelopes_own_sentence() {
    let kp = generate_recipient_keypair();
    let wrapped = wrap_data_key(&random_data_key(), &kp.public_key).expect("wrap");
    let sixteen = b64::encode([0u8; 16]);
    let four = b64::encode([0u8; 4]);
    for (w, s) in [
        ("not base64 at all!!", kp.secret_key.as_str()),
        (wrapped.as_str(), "not base64 at all!!"),
        (wrapped.as_str(), sixteen.as_str()),
        ("", kp.secret_key.as_str()),
        (four.as_str(), kp.secret_key.as_str()),
    ] {
        assert_eq!(unwrap_data_key(w, s).unwrap_err().0, CANNOT_OPEN, "{w:.8}/{s:.8}");
    }
}

#[test]
fn base64_round_trips_every_byte_value() {
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(b64::decode(&b64::encode(&all)).expect("b64"), all);
}

#[test]
fn chunk_limit_and_closed_stream_errors_match() {
    let mut enc = Encryptor::new(&random_data_key(), &binding()).expect("enc");
    assert_eq!(
        enc.push(&vec![0u8; CHUNK_BYTES + 1]).unwrap_err().0,
        "chunk of 524289 bytes is over the 524288 limit"
    );
    enc.finish().expect("final");
    assert_eq!(enc.push(&[1]).unwrap_err().0, "the archive stream is already closed");
}

#[test]
fn cipher_size_matches_what_is_sealed() {
    for n in [0usize, 1, CHUNK_BYTES, CHUNK_BYTES + 1, 3 * CHUNK_BYTES - 7] {
        let key = random_data_key();
        let mut enc = Encryptor::new(&key, &binding()).expect("enc");
        let plain = vec![5u8; n];
        let mut total = 0;
        for c in plain.chunks(CHUNK_BYTES) {
            total += enc.push(c).expect("push").len();
        }
        total += enc.finish().expect("final").len();
        assert_eq!(cipher_size_for(n as u64), total as u64, "{n}");
    }
}
