// SPDX-License-Identifier: Apache-2.0

//! PoSME seed derivation per draft-condrey-cfrg-posme.

use sha2::{Digest, Sha256};

const POSME_SEED_DST: &[u8] = b"PoP-PoSME-Seed-v1";

/// Genesis seed: `H(DST || doc_ref_cbor || jitter_or_nonce || vdf_output [|| challenge])`.
///
/// Binds the PoSME proof to the VDF time anchor, forcing sequential execution.
pub fn posme_seed_genesis(
    doc_ref_cbor: &[u8],
    jitter_or_nonce: &[u8; 32],
    vdf_output: &[u8; 32],
    challenge_nonce: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POSME_SEED_DST);
    hasher.update(doc_ref_cbor);
    hasher.update(jitter_or_nonce);
    hasher.update(vdf_output);
    if let Some(nonce) = challenge_nonce {
        hasher.update(nonce);
    }
    hasher.finalize().into()
}

/// Enhanced seed: `H(DST || prev_hash || jitter_cbor || phys_cbor || vdf_output [|| challenge])`.
pub fn posme_seed_enhanced(
    prev_hash: &[u8; 32],
    jitter_intervals_cbor: &[u8],
    physical_state_cbor: &[u8],
    vdf_output: &[u8; 32],
    challenge_nonce: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POSME_SEED_DST);
    hasher.update(prev_hash);
    hasher.update(jitter_intervals_cbor);
    hasher.update(physical_state_cbor);
    hasher.update(vdf_output);
    if let Some(nonce) = challenge_nonce {
        hasher.update(nonce);
    }
    hasher.finalize().into()
}

/// Core fallback seed: `H(DST || prev_hash || local_nonce || vdf_output [|| challenge])`.
pub fn posme_seed_core(
    prev_hash: &[u8; 32],
    local_nonce: &[u8; 32],
    vdf_output: &[u8; 32],
    challenge_nonce: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POSME_SEED_DST);
    hasher.update(prev_hash);
    hasher.update(local_nonce);
    hasher.update(vdf_output);
    if let Some(nonce) = challenge_nonce {
        hasher.update(nonce);
    }
    hasher.finalize().into()
}
