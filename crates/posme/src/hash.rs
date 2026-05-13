// SPDX-License-Identifier: Apache-2.0

//! BLAKE3-based hash primitives with domain separation per draft-condrey-cfrg-posme.

use crate::block::LAMBDA;
use crate::params::PosmeParams;

// Domain separation tags from the IETF draft.
pub const DST_INIT: &[u8] = b"PoSME-init-v1";
pub const DST_CAUSAL: &[u8] = b"PoSME-causal-v1";
pub const DST_TRANSCRIPT: &[u8] = b"PoSME-transcript-v1";
pub const DST_ADDR: &[u8] = b"PoSME-addr-v1";
pub const DST_FIAT_SHAMIR: &[u8] = b"PoSME-challenge-v1";

/// Compute BLAKE3(input_0 || input_1 || ... || input_n) -> 32 bytes.
pub fn posme_hash(inputs: &[&[u8]]) -> [u8; LAMBDA] {
    let mut hasher = blake3::Hasher::new();
    for input in inputs {
        hasher.update(input);
    }
    *hasher.finalize().as_bytes()
}

/// Integer-to-Octet-String Primitive: encode u32 as 4 big-endian bytes.
pub fn i2osp(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

/// XOF-based address derivation: BLAKE3 XOF at (DST_ADDR || cursor || I2OSP(index)),
/// producing 4 bytes interpreted as big-endian u32, masked to n-1.
///
/// Requires n to be a power of two (enforced by `PosmeParams::validate()`).
/// Uses bitwise AND instead of modulo for branchless, constant-time reduction.
pub fn addr_from(cursor: &[u8; LAMBDA], index: u32, n: u32) -> u32 {
    debug_assert!(n.is_power_of_two(), "addr_from requires n to be a power of 2");
    let h = posme_hash(&[DST_ADDR, cursor, &i2osp(index)]);
    u32::from_be_bytes([h[0], h[1], h[2], h[3]]) & (n - 1)
}

/// Derive Q unique Fiat-Shamir challenge step indices from (T_K, C_roots, params).
///
/// The params are bound into sigma so that a proof generated at one difficulty
/// tier cannot be replayed as a proof for a different tier.
pub fn derive_challenges(
    final_transcript: &[u8; LAMBDA],
    root_chain_commitment: &[u8; LAMBDA],
    params: &PosmeParams,
) -> Vec<u32> {
    let param_bytes = params.to_challenge_bytes();
    let sigma = posme_hash(&[
        DST_FIAT_SHAMIR,
        final_transcript,
        root_chain_commitment,
        &param_bytes,
    ]);
    let q = params.challenges;
    let k = params.total_steps;
    let mut seen = std::collections::BTreeSet::new();
    let mut challenges = Vec::with_capacity(q as usize);
    let mut counter = 0u32;
    let max_iters = (q as u32).saturating_mul(10).max(1000);
    while challenges.len() < q as usize {
        if counter >= max_iters {
            break;
        }
        let h = posme_hash(&[&sigma, &i2osp(counter)]);
        let val = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % k;
        let step = val + 1;
        if seen.insert(step) {
            challenges.push(step);
        }
        counter += 1;
    }
    debug_assert_eq!(
        challenges.len(),
        q as usize,
        "challenge derivation incomplete: got {} of {} in {} iterations",
        challenges.len(),
        q,
        max_iters
    );
    challenges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let a = posme_hash(&[b"hello", b"world"]);
        let b = posme_hash(&[b"hello", b"world"]);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_domain_separation() {
        let a = posme_hash(&[DST_INIT, b"seed"]);
        let b = posme_hash(&[DST_CAUSAL, b"seed"]);
        assert_ne!(a, b);
    }

    #[test]
    fn addr_in_range() {
        let cursor = posme_hash(&[b"test"]);
        for n in [1u32, 2, 1024, 1 << 20] {
            for j in 0..16 {
                assert!(addr_from(&cursor, j, n) < n);
            }
        }
    }

    #[test]
    fn addr_deterministic() {
        let cursor = posme_hash(&[b"cursor"]);
        let a = addr_from(&cursor, 0, 1024);
        let b = addr_from(&cursor, 0, 1024);
        assert_eq!(a, b);
    }

    #[test]
    fn addr_varies_with_index() {
        let cursor = posme_hash(&[b"cursor"]);
        let a = addr_from(&cursor, 0, 1 << 24);
        let b = addr_from(&cursor, 1, 1 << 24);
        // With 2^24 possible values, collision probability is negligible.
        assert_ne!(a, b);
    }
}
