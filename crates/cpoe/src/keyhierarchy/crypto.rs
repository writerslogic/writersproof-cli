// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::DateTimeNanosExt;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::error::KeyHierarchyError;

pub(crate) const IDENTITY_DOMAIN: &str = "cpoe-identity-v1";
pub(crate) const SESSION_DOMAIN: &str = "cpoe-session-v1";
pub(crate) const RATCHET_INIT_DOMAIN: &str = "cpoe-ratchet-init-v1";
pub(crate) const RATCHET_ADVANCE_DOMAIN: &str = "cpoe-ratchet-advance-v1";
pub(crate) const SIGNING_KEY_DOMAIN: &str = "cpoe-signing-key-v1";

/// HKDF-SHA256 key derivation (RFC 5869).
///
/// - `ikm`: input keying material (e.g. identity seed or ratchet state).
/// - `salt`: extraction-phase salt. Callers pass domain-separation labels
///   (e.g. `SESSION_DOMAIN`) here, which is non-standard but acceptable
///   because it binds the PRK to a unique domain before expansion.
/// - `info`: expansion-phase context (e.g. session-specific input, or empty).
// NOTE: Callers use domain labels as salt for extraction-phase separation.
// This is the reverse of the typical convention (domain in `info`), but the
// cryptographic result is sound and changing it would break all derived keys.
pub fn hkdf_expand(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, KeyHierarchyError> {
    crate::utils::key_derivation::hkdf_sha256(ikm, Some(salt), info)
        .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))
}

pub(crate) fn build_cert_data(
    session_id: [u8; 32],
    session_pub_key: &[u8],
    created_at: DateTime<Utc>,
    document_hash: [u8; 32],
) -> Vec<u8> {
    build_cert_data_with_expiry(session_id, session_pub_key, created_at, document_hash, None)
}

pub(crate) fn build_cert_data_with_expiry(
    session_id: [u8; 32],
    session_pub_key: &[u8],
    created_at: DateTime<Utc>,
    document_hash: [u8; 32],
    expires_at: Option<DateTime<Utc>>,
) -> Vec<u8> {
    // Ed25519 public keys must be exactly 32 bytes.  A wrong-length key
    // produces an ambiguous cert_data blob (no length prefix) that cannot
    // be verified, and could allow certificate substitution.
    debug_assert_eq!(
        session_pub_key.len(),
        32,
        "session_pub_key must be 32 bytes (Ed25519), got {}",
        session_pub_key.len()
    );
    let mut data = Vec::with_capacity(32 + 32 + 8 + 32 + 9);
    data.extend_from_slice(&session_id);
    data.extend_from_slice(session_pub_key);
    let nanos = created_at.timestamp_nanos_safe();
    if nanos < 0 {
        // Pre-epoch timestamps would wrap in u64 encoding; clamp to 0
        // to prevent certificate substitution attacks
        log::warn!("build_cert_data: clamping pre-epoch timestamp to zero");
    }
    data.extend_from_slice(&(nanos.max(0) as u64).to_be_bytes());
    data.extend_from_slice(&document_hash);
    if let Some(exp) = expires_at {
        data.push(1u8);
        let exp_nanos = exp.timestamp_nanos_safe().max(0) as u64;
        data.extend_from_slice(&exp_nanos.to_be_bytes());
    }
    data
}

pub fn fingerprint_for_public_key(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[0..8])
}

/// SHA-256(session_id || data_hash || mmr_root) nonce that binds a TPM quote
/// to the exact authorship chain state, preventing cross-session quote replay.
pub fn compute_entangled_nonce(
    session_id: &[u8; 32],
    data_hash: &[u8; 32],
    mmr_root: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cpoe-entangled-nonce-v1");
    hasher.update(session_id);
    hasher.update(data_hash);
    hasher.update(mmr_root);
    hasher.finalize().into()
}
