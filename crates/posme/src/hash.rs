// SPDX-License-Identifier: Apache-2.0

//! BLAKE3-based hash primitives with domain separation per draft-condrey-cfrg-posme.

use crate::block::LAMBDA;
use crate::params::PosmeParams;

pub(crate) const DST_INIT: &[u8] = b"PoSME-init-v1";
pub(crate) const DST_CAUSAL: &[u8] = b"PoSME-causal-v1";
pub(crate) const DST_TRANSCRIPT: &[u8] = b"PoSME-transcript-v1";
pub(crate) const DST_ADDR: &[u8] = b"PoSME-addr-v1";
pub(crate) const DST_FIAT_SHAMIR: &[u8] = b"PoSME-challenge-v1";

/// BLAKE3(input_0 || ... || input_n) -> 32 bytes.
pub(crate) fn posme_hash(inputs: &[&[u8]]) -> [u8; LAMBDA] {
    let mut hasher = blake3::Hasher::new();
    for input in inputs {
        hasher.update(input);
    }
    *hasher.finalize().as_bytes()
}

/// I2OSP: u32 -> 4 big-endian bytes.
pub(crate) fn i2osp(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

/// Address derivation via BLAKE3, masked to n-1 (n must be power of 2).
pub(crate) fn addr_from(cursor: &[u8; LAMBDA], index: u32, n: u32) -> u32 {
    debug_assert!(n.is_power_of_two());
    let h = posme_hash(&[DST_ADDR, cursor, &i2osp(index)]);
    u32::from_be_bytes([h[0], h[1], h[2], h[3]]) & (n - 1)
}

/// Derive Q unique Fiat-Shamir challenge indices via BLAKE3 XOF with rejection
/// sampling. Params are bound into sigma to prevent cross-tier proof replay.
pub(crate) fn derive_challenges(
    final_transcript: &[u8; LAMBDA],
    root_chain_commitment: &[u8; LAMBDA],
    params: &PosmeParams,
) -> Vec<u32> {
    let param_bytes = params.to_challenge_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(DST_FIAT_SHAMIR);
    hasher.update(final_transcript);
    hasher.update(root_chain_commitment);
    hasher.update(&param_bytes);
    let mut reader = hasher.finalize_xof();

    let q = params.challenges as usize;
    let k = params.total_steps;
    // Reject raw < (2^32 mod k) to eliminate modulo bias. Zero when k is power-of-2.
    let reject_below = (u32::MAX - k + 1) % k;

    let mut seen = std::collections::BTreeSet::new();
    let mut challenges = Vec::with_capacity(q);
    let mut buf = [0u8; 4];

    while challenges.len() < q {
        reader.fill(&mut buf);
        let raw = u32::from_be_bytes(buf);
        if raw < reject_below {
            continue;
        }
        let step = (raw % k) + 1;
        if seen.insert(step) {
            challenges.push(step);
        }
    }

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
        assert_eq!(addr_from(&cursor, 0, 1024), addr_from(&cursor, 0, 1024));
    }

    #[test]
    fn addr_varies_with_index() {
        let cursor = posme_hash(&[b"cursor"]);
        assert_ne!(addr_from(&cursor, 0, 1 << 24), addr_from(&cursor, 1, 1 << 24));
    }

    #[test]
    fn derive_challenges_deterministic() {
        let t = posme_hash(&[b"transcript"]);
        let r = posme_hash(&[b"roots"]);
        let params = PosmeParams::test();
        assert_eq!(derive_challenges(&t, &r, &params), derive_challenges(&t, &r, &params));
    }

    #[test]
    fn derive_challenges_unique() {
        let t = posme_hash(&[b"transcript"]);
        let r = posme_hash(&[b"roots"]);
        let params = PosmeParams::test();
        let c = derive_challenges(&t, &r, &params);
        assert_eq!(c.len(), params.challenges as usize);
        let mut deduped = c.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(c.len(), deduped.len());
    }

    #[test]
    fn derive_challenges_in_range() {
        let t = posme_hash(&[b"transcript"]);
        let r = posme_hash(&[b"roots"]);
        let params = PosmeParams::test();
        for &step in &derive_challenges(&t, &r, &params) {
            assert!(step >= 1 && step <= params.total_steps);
        }
    }
}
