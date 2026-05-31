// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Centralized HKDF-SHA256 key derivation (RFC 5869).
//!
//! All standard HKDF usage should go through these functions to ensure
//! consistent error handling, zeroization, and domain separation.
//!
//! Remaining inline HKDF sites: `crypto.rs` PoP functions (returns PRK
//! object for multi-expansion) and `vdf/swf_argon2.rs` (PRK rejection
//! sampling loop with 4-byte outputs).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Core HKDF-SHA256: Extract-then-Expand with optional salt, const-generic output size.
///
/// Valid for any `N` in 1..=8160 (255 * 32). Returns a zeroizing fixed-size array.
pub fn hkdf_sha256_n<const N: usize>(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<Zeroizing<[u8; N]>> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new([0u8; N]);
    hk.expand(info, okm.as_mut())
        .map_err(|_| Error::crypto("HKDF-SHA256 expand failed"))?;
    Ok(okm)
}

/// HKDF-SHA256: 32-byte zeroizing output (most common case).
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    hkdf_sha256_n::<32>(ikm, salt, info)
}

/// HKDF-SHA256 with non-zeroizing 32-byte output (for non-secret derived values).
pub fn hkdf_sha256_raw(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<[u8; 32]> {
    Ok(*hkdf_sha256_n::<32>(ikm, salt, info)?)
}

// ── Purpose-specific wrappers ────────────────────────────────────────────

/// Derive an encryption key for fingerprint storage (legacy migration path).
///
/// DST: salt=`cpoe-fingerprint-storage-v1`, info=`fingerprint-encryption-key`
pub fn derive_fingerprint_storage_key(key_material: &[u8]) -> Result<[u8; 32]> {
    hkdf_sha256_raw(
        key_material,
        Some(b"cpoe-fingerprint-storage-v1"),
        b"fingerprint-encryption-key",
    )
}

/// Derive a software-wrap encryption key for sealed identity.
///
/// DST: info=`cpoe-software-wrap-v2`
pub fn derive_software_wrap_key(machine_salt: &[u8], random_salt: &[u8]) -> Result<[u8; 32]> {
    hkdf_sha256_raw(machine_salt, Some(random_salt), b"cpoe-software-wrap-v2")
}

/// Re-derive a signing key from master key and behavioral entropy.
///
/// DST: info=`cpoe-behavioral-entropy-v1`
///
/// Panics only if HKDF-SHA256 expand fails for 32 bytes (impossible per RFC 5869).
pub fn derive_behavioral_signing_key(
    master_key_bytes: &[u8],
    entropy_pool: &[u8],
) -> Zeroizing<[u8; 32]> {
    hkdf_sha256(
        master_key_bytes,
        Some(entropy_pool),
        b"cpoe-behavioral-entropy-v1",
    )
    .expect("HKDF-SHA256 expand of 32 bytes is infallible")
}

/// Derive a binding MAC key from jitter entropy.
///
/// DST: info=`cpoe-binding-mac-key-v1`
pub fn derive_binding_mac_key(entropy_hash: &[u8]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256(entropy_hash, None, b"cpoe-binding-mac-key-v1")
        .expect("32 bytes is valid HKDF-Expand length")
}

/// Derive a Lamport one-shot signing seed from a master signing key.
///
/// DST: salt=`cpoe-lamport-event-v1`, info=event_hash
pub fn derive_lamport_seed(
    signing_key_bytes: &[u8],
    event_hash: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    hkdf_sha256(signing_key_bytes, Some(b"cpoe-lamport-event-v1"), event_hash)
}

/// Derive a guilloche visual fingerprint seed from a signing key.
///
/// DST: salt=`cpoe-guilloche-v1`, info=`cpoe-guilloche-seed-v1`
pub fn derive_guilloche_seed(signing_key_bytes: &[u8]) -> Result<[u8; 32]> {
    hkdf_sha256_raw(
        signing_key_bytes,
        Some(b"cpoe-guilloche-v1"),
        b"cpoe-guilloche-seed-v1",
    )
}

/// Derive a purpose-specific HMAC key from a signing key via HKDF-SHA256.
///
/// Each purpose gets a cryptographically independent key, so compromising one
/// store's HMAC key does not affect the others. The `purpose` string is used
/// as the HKDF info parameter for domain separation.
///
/// DST: salt=`cpoe-hmac-key-derive-v2`, info=purpose
pub fn derive_hmac_key(signing_key_bytes: &[u8], purpose: &str) -> Zeroizing<Vec<u8>> {
    let key = hkdf_sha256(signing_key_bytes, Some(b"cpoe-hmac-key-derive-v2"), purpose.as_bytes())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Zeroizing::new(key.to_vec())
}

/// Derive a PUF challenge-response (32 bytes).
///
/// DST: info=`puf-response-v1`
pub fn derive_puf_response(seed: &[u8], challenge: &[u8]) -> Result<[u8; 32]> {
    hkdf_sha256_raw(seed, Some(challenge), b"puf-response-v1")
}

/// Derive a 64-byte silicon-bound seed from mnemonic entropy and PUF fingerprint.
///
/// DST: info=`cpoe-silicon-seed-v1`
pub fn derive_silicon_seed(
    raw_seed: &[u8],
    puf_fingerprint: &[u8],
) -> Result<Zeroizing<[u8; 64]>> {
    hkdf_sha256_n::<64>(raw_seed, Some(puf_fingerprint), b"cpoe-silicon-seed-v1")
}

/// Derive a snapshot blob encryption key (32 bytes, zeroizing).
///
/// DST: salt=`writerslogic-snapshot-v1`, info=content_hash
pub fn derive_snapshot_key(
    signing_key_bytes: &[u8],
    content_hash: &[u8],
) -> Zeroizing<[u8; 32]> {
    hkdf_sha256(signing_key_bytes, Some(b"writerslogic-snapshot-v1"), content_hash)
        .expect("32-byte output is within HKDF-SHA256 limit")
}

/// Derive a snapshot blob nonce (12 bytes).
///
/// DST: salt=`writerslogic-snapshot-nonce-v1`, info=content_hash
pub fn derive_snapshot_nonce(signing_key_bytes: &[u8], content_hash: &[u8]) -> [u8; 12] {
    *hkdf_sha256_n::<12>(
        signing_key_bytes,
        Some(b"writerslogic-snapshot-nonce-v1"),
        content_hash,
    )
    .expect("12-byte output is within HKDF-SHA256 limit")
}

/// IPC session keys derived from an ECDH shared secret.
#[derive(Debug)]
pub struct IpcSessionKeys {
    pub aes_key: [u8; 32],
    pub client_nonce_prefix: [u8; 4],
    pub server_nonce_prefix: [u8; 4],
}

/// Derive IPC session keys (AES-256-GCM key + directional nonce prefixes).
///
/// DST: salt=`cpoe-ipc-v1`, info varies per expansion
pub fn derive_ipc_session_keys(
    shared_secret: &[u8],
    client_pubkey: &[u8],
    server_pubkey: &[u8],
) -> Result<IpcSessionKeys> {
    let hk = Hkdf::<Sha256>::new(Some(b"cpoe-ipc-v1"), shared_secret);

    let mut info = Vec::with_capacity(15 + client_pubkey.len() + server_pubkey.len());
    info.extend_from_slice(b"aes-256-gcm-key");
    info.extend_from_slice(client_pubkey);
    info.extend_from_slice(server_pubkey);

    let mut aes_key = [0u8; 32];
    hk.expand(&info, &mut aes_key)
        .map_err(|_| Error::crypto("HKDF expand failed for IPC AES key"))?;

    let mut client_nonce_prefix = [0u8; 4];
    hk.expand(b"nonce-prefix-client", &mut client_nonce_prefix)
        .map_err(|_| Error::crypto("HKDF expand failed for IPC client nonce prefix"))?;

    let mut server_nonce_prefix = [0u8; 4];
    hk.expand(b"nonce-prefix-server", &mut server_nonce_prefix)
        .map_err(|_| Error::crypto("HKDF expand failed for IPC server nonce prefix"))?;

    Ok(IpcSessionKeys {
        aes_key,
        client_nonce_prefix,
        server_nonce_prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha256_deterministic() {
        let a = hkdf_sha256(b"ikm", Some(b"salt"), b"info").unwrap();
        let b = hkdf_sha256(b"ikm", Some(b"salt"), b"info").unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn hkdf_sha256_different_salts_differ() {
        let a = hkdf_sha256(b"ikm", Some(b"salt-a"), b"info").unwrap();
        let b = hkdf_sha256(b"ikm", Some(b"salt-b"), b"info").unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn hkdf_sha256_different_info_differ() {
        let a = hkdf_sha256(b"ikm", Some(b"salt"), b"info-a").unwrap();
        let b = hkdf_sha256(b"ikm", Some(b"salt"), b"info-b").unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn hkdf_sha256_no_salt() {
        let result = hkdf_sha256(b"ikm", None, b"info");
        assert!(result.is_ok());
    }

    #[test]
    fn hkdf_sha256_raw_matches_zeroizing() {
        let z = hkdf_sha256(b"ikm", Some(b"salt"), b"info").unwrap();
        let r = hkdf_sha256_raw(b"ikm", Some(b"salt"), b"info").unwrap();
        assert_eq!(*z, r);
    }

    #[test]
    fn derive_fingerprint_storage_key_deterministic() {
        let a = derive_fingerprint_storage_key(b"key-material").unwrap();
        let b = derive_fingerprint_storage_key(b"key-material").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_software_wrap_key_different_salts() {
        let a = derive_software_wrap_key(b"machine", b"random-a").unwrap();
        let b = derive_software_wrap_key(b"machine", b"random-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_behavioral_signing_key_deterministic() {
        let a = derive_behavioral_signing_key(b"master", b"entropy");
        let b = derive_behavioral_signing_key(b"master", b"entropy");
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_binding_mac_key_deterministic() {
        let a = derive_binding_mac_key(b"entropy-hash");
        let b = derive_binding_mac_key(b"entropy-hash");
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_lamport_seed_deterministic() {
        let a = derive_lamport_seed(b"signing-key", b"event-hash").unwrap();
        let b = derive_lamport_seed(b"signing-key", b"event-hash").unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_lamport_seed_different_events_differ() {
        let a = derive_lamport_seed(b"key", b"event-a").unwrap();
        let b = derive_lamport_seed(b"key", b"event-b").unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn derive_guilloche_seed_deterministic() {
        let a = derive_guilloche_seed(b"signing-key").unwrap();
        let b = derive_guilloche_seed(b"signing-key").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_hmac_key_different_purposes_differ() {
        let a = derive_hmac_key(b"key", "events");
        let b = derive_hmac_key(b"key", "access-log");
        assert_ne!(*a, *b);
    }

    #[test]
    fn hkdf_sha256_n_64_bytes() {
        let result = hkdf_sha256_n::<64>(b"ikm", Some(b"salt"), b"info");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn hkdf_sha256_n_12_bytes() {
        let result = hkdf_sha256_n::<12>(b"ikm", Some(b"salt"), b"info");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 12);
    }

    #[test]
    fn derive_puf_response_deterministic() {
        let a = derive_puf_response(b"seed", b"challenge").unwrap();
        let b = derive_puf_response(b"seed", b"challenge").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_puf_response_different_challenges_differ() {
        let a = derive_puf_response(b"seed", b"challenge-a").unwrap();
        let b = derive_puf_response(b"seed", b"challenge-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_silicon_seed_is_64_bytes() {
        let result = derive_silicon_seed(b"mnemonic-seed", b"puf-fp").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn derive_snapshot_key_deterministic() {
        let a = derive_snapshot_key(b"01234567890123456789012345678901", b"hash");
        let b = derive_snapshot_key(b"01234567890123456789012345678901", b"hash");
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_snapshot_nonce_is_12_bytes() {
        let n = derive_snapshot_nonce(b"01234567890123456789012345678901", b"hash");
        assert_eq!(n.len(), 12);
    }

    #[test]
    fn derive_ipc_session_keys_produces_distinct_prefixes() {
        let keys =
            derive_ipc_session_keys(b"shared-secret", b"client-pub", b"server-pub").unwrap();
        assert_ne!(keys.client_nonce_prefix, keys.server_nonce_prefix);
    }

    #[test]
    fn all_wrappers_produce_independent_keys() {
        let ikm = b"same-key-material-for-all";
        let fp = derive_fingerprint_storage_key(ikm).unwrap();
        let sw = derive_software_wrap_key(ikm, b"salt").unwrap();
        let bk = derive_behavioral_signing_key(ikm, b"entropy");
        let bm = derive_binding_mac_key(ikm);
        let ls = derive_lamport_seed(ikm, b"hash").unwrap();
        let gs = derive_guilloche_seed(ikm).unwrap();
        let hm = derive_hmac_key(ikm, "test");

        let keys: Vec<&[u8]> = vec![&fp, &sw, &*bk, &*bm, &*ls, &gs, &*hm];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "keys {i} and {j} collide");
            }
        }
    }
}
