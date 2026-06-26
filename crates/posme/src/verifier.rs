// SPDX-License-Identifier: Apache-2.0

//! Stateless PoSME proof verification (no arena allocation).

use crate::block::LAMBDA;
use crate::error::{PosmeError, Result};
use crate::hash::{
    addr_from, derive_challenges, i2osp, posme_hash, DST_CAUSAL, DST_INIT, DST_TRANSCRIPT,
};
use crate::merkle;
use crate::proof::{
    PosmeProof, StepProof, INIT_WITNESS_COUNT, PROOF_ALGORITHM_POSME,
    PROOF_ALGORITHM_POSME_ENTANGLED,
};
use subtle::ConstantTimeEq;

/// Uniform random bytes have expected variance ~5460. Threshold set at 50.0
/// to reject identical/near-identical jitter while avoiding false positives.
const MIN_JITTER_BYTE_VARIANCE: f64 = 50.0;

fn validate_jitter_entropy(entanglement_points: &[(u32, [u8; 32])]) -> Result<()> {
    if entanglement_points.len() < 2 {
        return Ok(());
    }
    let total_bytes = entanglement_points.len() * 32;
    let mut sum: f64 = 0.0;
    let mut sum_sq: f64 = 0.0;
    for (_, jh) in entanglement_points {
        for &b in jh {
            let v = b as f64;
            sum += v;
            sum_sq += v * v;
        }
    }
    let mean = sum / total_bytes as f64;
    let variance = (sum_sq / total_bytes as f64) - (mean * mean);
    if variance < MIN_JITTER_BYTE_VARIANCE {
        return Err(PosmeError::jitter_entropy(
            variance,
            MIN_JITTER_BYTE_VARIANCE,
        ));
    }
    Ok(())
}

fn verify_root_chain_path(
    commitment: &[u8; LAMBDA],
    index: usize,
    value: &[u8; LAMBDA],
    path: &[[u8; LAMBDA]],
    total_roots: usize,
) -> bool {
    let n = total_roots.next_power_of_two();
    let expected_depth = (n as u32).trailing_zeros() as usize;
    if path.len() != expected_depth {
        return false;
    }
    let mut current = *value;
    let mut pos = n + index;
    for sibling in path {
        current = if pos & 1 == 0 {
            posme_hash(&[&current, sibling])
        } else {
            posme_hash(&[sibling, &current])
        };
        pos /= 2;
    }
    current.ct_eq(commitment).into()
}

pub fn verify(seed: &[u8], proof: &PosmeProof) -> Result<()> {
    proof.params.validate()?;

    if proof.proof_algorithm != PROOF_ALGORITHM_POSME
        && proof.proof_algorithm != PROOF_ALGORITHM_POSME_ENTANGLED
    {
        return Err(PosmeError::verification_failed(format!(
            "unknown proof algorithm: {}",
            proof.proof_algorithm
        )));
    }

    if proof.proof_algorithm == PROOF_ALGORITHM_POSME_ENTANGLED {
        validate_jitter_entropy(&proof.entanglement_points)?;
    }

    let n = proof.params.arena_blocks;
    let k = proof.params.total_steps;
    let d = proof.params.reads_per_step;
    let total_roots = (k as usize)
        .checked_add(1)
        .ok_or_else(|| PosmeError::invalid_params("total_steps overflow in root count"))?;

    // Verify root_0 is in the root chain.
    if !verify_root_chain_path(
        &proof.root_chain_commitment,
        0,
        &proof.root_0,
        &proof.root_0_path,
        total_roots,
    ) {
        return Err(PosmeError::RootChainFailed { step_id: 0 });
    }

    // Verify init witnesses bind root_0 to the seed.
    if proof.init_witnesses.len() < INIT_WITNESS_COUNT {
        return Err(PosmeError::verification_failed(format!(
            "insufficient init witnesses: {} < {INIT_WITNESS_COUNT}",
            proof.init_witnesses.len()
        )));
    }

    // Re-derive expected witness indices (n is power-of-2, bitmask is bias-free).
    let sigma = posme_hash(&[b"PoSME-init-witness-v1", seed, &proof.root_0]);
    let mut expected_indices = Vec::with_capacity(INIT_WITNESS_COUNT);
    let mut counter = 0u32;
    while expected_indices.len() < INIT_WITNESS_COUNT {
        let h = posme_hash(&[&sigma, &i2osp(counter)]);
        let idx = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) & (n - 1);
        counter += 1;
        if expected_indices.contains(&idx) {
            continue;
        }
        expected_indices.push(idx);
    }
    for (w, &expected_idx) in proof.init_witnesses.iter().zip(&expected_indices) {
        if w.index != expected_idx {
            return Err(PosmeError::verification_failed(format!(
                "init witness index mismatch: got {}, expected {expected_idx}",
                w.index
            )));
        }
        let expected_data = if w.index == 0 {
            posme_hash(&[DST_INIT, seed, &i2osp(0)])
        } else {
            w.block.data
        };
        let expected_causal = posme_hash(&[DST_CAUSAL, seed, &i2osp(w.index)]);
        if w.index == 0 && bool::from(w.block.data.ct_ne(&expected_data)) {
            return Err(PosmeError::verification_failed(
                "init block 0 data mismatch",
            ));
        }
        if bool::from(w.block.causal.ct_ne(&expected_causal)) {
            return Err(PosmeError::verification_failed(format!(
                "init block {} causal mismatch",
                w.index
            )));
        }
        if !merkle::verify_path(&proof.root_0, w.index, &w.block, &w.merkle_path, n) {
            return Err(PosmeError::MerkleVerifyFailed {
                step_id: 0,
                address: w.index,
            });
        }
    }

    let t_0 = posme_hash(&[DST_TRANSCRIPT, seed, &proof.root_0]);

    let expected_challenges = derive_challenges(
        &proof.final_transcript,
        &proof.root_chain_commitment,
        &proof.params,
    );
    let proof_step_ids: Vec<u32> = proof.challenged_steps.iter().map(|s| s.step_id).collect();
    if proof_step_ids != expected_challenges {
        return Err(PosmeError::ChallengeMismatch);
    }

    let ctx = VerifyCtx {
        n,
        d,
        k,
        total_roots,
        t_0,
        max_writer_depth: proof.params.recursion_depth.saturating_sub(1),
    };
    let mut step_transcripts: Vec<(u32, [u8; LAMBDA])> =
        Vec::with_capacity(proof.challenged_steps.len());

    for sp in &proof.challenged_steps {
        let transcript_val = verify_step(sp, proof, &ctx, ctx.max_writer_depth)?;
        step_transcripts.push((sp.step_id, transcript_val));
    }

    // Cross-check transcript chain between consecutive challenged steps.
    let entangle_map: std::collections::BTreeMap<u32, [u8; 32]> =
        proof.entanglement_points.iter().copied().collect();
    if entangle_map.len() != proof.entanglement_points.len() {
        return Err(PosmeError::verification_failed(
            "duplicate step_id in entanglement_points",
        ));
    }
    let mut sorted_transcripts = step_transcripts.clone();
    sorted_transcripts.sort_by_key(|&(step, _)| step);
    for pair in sorted_transcripts.windows(2) {
        let (step_a, mut transcript_a) = pair[0];
        let step_b_id = pair[1].0;
        let cursor_in_b = proof
            .challenged_steps
            .iter()
            .find(|s| s.step_id == step_b_id)
            .ok_or_else(|| {
                PosmeError::verification_failed(format!(
                    "challenged step {step_b_id} missing from proof"
                ))
            })?
            .cursor_in;
        if let Some(jh) = entangle_map.get(&step_a) {
            transcript_a = posme_hash(&[b"PoSME-entangle-v1", &transcript_a, jh]);
        }
        if step_b_id == step_a + 1 && bool::from(cursor_in_b.ct_ne(&transcript_a)) {
            return Err(PosmeError::TranscriptMismatch { step_id: step_b_id });
        }
    }

    Ok(())
}

struct VerifyCtx {
    n: u32,
    d: u8,
    k: u32,
    total_roots: usize,
    t_0: [u8; LAMBDA],
    max_writer_depth: u8,
}

fn verify_symbiotic_write(
    sp: &StepProof,
    step: u32,
    n: u32,
    d: u8,
    cursor: &[u8; LAMBDA],
) -> Result<()> {
    let expected_addr = addr_from(cursor, u32::from(d), n);
    if expected_addr != sp.write.address {
        return Err(PosmeError::WriteMismatch { step_id: step });
    }
    if !merkle::verify_path(
        &sp.root_before,
        sp.write.address,
        &sp.write.old_block,
        &sp.write.merkle_path,
        n,
    ) {
        return Err(PosmeError::MerkleVerifyFailed {
            step_id: step,
            address: sp.write.address,
        });
    }
    let expected_data = posme_hash(&[&sp.write.old_block.data, cursor, &sp.write.old_block.causal]);
    let expected_causal = posme_hash(&[&sp.write.old_block.causal, cursor, &i2osp(step)]);
    if sp.write.new_block.data.ct_ne(&expected_data).into()
        || sp.write.new_block.causal.ct_ne(&expected_causal).into()
    {
        return Err(PosmeError::WriteMismatch { step_id: step });
    }
    if !merkle::verify_path(
        &sp.root_after,
        sp.write.address,
        &sp.write.new_block,
        &sp.write.merkle_path,
        n,
    ) {
        return Err(PosmeError::MerkleVerifyFailed {
            step_id: step,
            address: sp.write.address,
        });
    }
    Ok(())
}

fn verify_step(
    sp: &StepProof,
    proof: &PosmeProof,
    ctx: &VerifyCtx,
    writer_depth: u8,
) -> std::result::Result<[u8; LAMBDA], PosmeError> {
    let step = sp.step_id;
    if sp.writers.len() > sp.reads.len() {
        return Err(PosmeError::verification_failed(format!(
            "step {step}: writers count ({}) exceeds reads count ({})",
            sp.writers.len(),
            sp.reads.len()
        )));
    }
    if step == 0 || step > ctx.k {
        return Err(PosmeError::verification_failed(format!(
            "step_id {step} out of valid range [1, {}]",
            ctx.k
        )));
    }
    let n = ctx.n;

    if !verify_root_chain_path(
        &proof.root_chain_commitment,
        step as usize - 1,
        &sp.root_before,
        &sp.root_chain_paths.0,
        ctx.total_roots,
    ) {
        return Err(PosmeError::RootChainFailed { step_id: step });
    }
    if !verify_root_chain_path(
        &proof.root_chain_commitment,
        step as usize,
        &sp.root_after,
        &sp.root_chain_paths.1,
        ctx.total_roots,
    ) {
        return Err(PosmeError::RootChainFailed { step_id: step });
    }

    for rw in &sp.reads {
        if !merkle::verify_path(&sp.root_before, rw.address, &rw.block, &rw.merkle_path, n) {
            return Err(PosmeError::MerkleVerifyFailed {
                step_id: step,
                address: rw.address,
            });
        }
    }

    let cursor_in = sp.cursor_in;
    let mut cursor = cursor_in;
    for (j, rw) in sp.reads.iter().enumerate() {
        let expected_addr = addr_from(&cursor, j as u32, n);
        if expected_addr != rw.address {
            return Err(PosmeError::AddressMismatch {
                step_id: step,
                read_index: j as u32,
                expected: expected_addr,
                got: rw.address,
            });
        }
        cursor = posme_hash(&[&cursor, &rw.block.data, &rw.block.causal]);
    }

    verify_symbiotic_write(sp, step, n, ctx.d, &cursor)?;

    for (j, w) in sp.writers.iter().enumerate() {
        if j >= sp.reads.len() {
            return Err(PosmeError::verification_failed(format!(
                "writer index {} out of bounds for reads (len {}) at step {}",
                j,
                sp.reads.len(),
                step
            )));
        }
        if w.proof_type == 0 {
            if let Some(ref path) = w.init_merkle_path {
                let read = &sp.reads[j];
                if !merkle::verify_path(&proof.root_0, read.address, &read.block, path, n) {
                    return Err(PosmeError::MerkleVerifyFailed {
                        step_id: step,
                        address: read.address,
                    });
                }
            }
        }
        if let Some(ref witness) = w.step_witness {
            if writer_depth == 0 {
                return Err(PosmeError::verification_failed(format!(
                    "writer chain exceeds max depth at step {}",
                    step
                )));
            }
            if witness.step_id == 0 || witness.step_id >= step {
                return Err(PosmeError::verification_failed(format!(
                    "writer step {} for read {} at step {} is not a valid prior step",
                    witness.step_id, j, step
                )));
            }
            if witness.step_id != w.writer_step_id {
                return Err(PosmeError::verification_failed(format!(
                    "writer witness step_id {} != claimed writer_step_id {}",
                    witness.step_id, w.writer_step_id
                )));
            }
            verify_step(witness, proof, ctx, writer_depth - 1)?;
            let read = &sp.reads[j];
            if witness.write.address != read.address {
                return Err(PosmeError::verification_failed(format!(
                    "writer step {} wrote to address {} but read {} is at address {}",
                    witness.step_id, witness.write.address, j, read.address
                )));
            }
            if bool::from(witness.write.new_block.data.ct_ne(&read.block.data))
                || bool::from(witness.write.new_block.causal.ct_ne(&read.block.causal))
            {
                return Err(PosmeError::verification_failed(format!(
                    "writer step {} output doesn't match read block at address {}",
                    witness.step_id, read.address
                )));
            }
        }
    }

    let expected_transcript = posme_hash(&[&cursor_in, &i2osp(step), &cursor, &sp.root_after]);

    if step == ctx.k {
        let mut final_expected = expected_transcript;
        for &(ep_step, ref jh) in &proof.entanglement_points {
            if ep_step == step {
                final_expected = posme_hash(&[b"PoSME-entangle-v1", &final_expected, jh]);
            }
        }
        if final_expected.ct_ne(&proof.final_transcript).into() {
            return Err(PosmeError::TranscriptMismatch { step_id: step });
        }
    }

    if step == 1 && bool::from(cursor_in.ct_ne(&ctx.t_0)) {
        return Err(PosmeError::TranscriptMismatch { step_id: step });
    }

    Ok(expected_transcript)
}

#[cfg(test)]
#[cfg(feature = "prover")]
mod tests {
    use super::*;
    use crate::params::PosmeParams;
    use crate::prover;

    fn test_params() -> PosmeParams {
        PosmeParams::test()
    }

    #[test]
    fn roundtrip_verify() {
        let seed = b"roundtrip-test";
        let proof = prover::execute(seed, &test_params()).unwrap();
        verify(seed, &proof).unwrap();
    }

    #[test]
    fn wrong_seed_fails() {
        let proof = prover::execute(b"seed-a", &test_params()).unwrap();
        assert!(verify(b"seed-b", &proof).is_err());
    }

    #[test]
    fn tampered_transcript_fails() {
        let seed = b"tamper-test";
        let mut proof = prover::execute(seed, &test_params()).unwrap();
        proof.final_transcript[0] ^= 0xff;
        assert!(verify(seed, &proof).is_err());
    }

    #[test]
    fn tampered_root_chain_fails() {
        let seed = b"tamper-root";
        let mut proof = prover::execute(seed, &test_params()).unwrap();
        proof.root_chain_commitment[0] ^= 0xff;
        assert!(verify(seed, &proof).is_err());
    }

    #[test]
    fn tampered_init_witness_fails() {
        let seed = b"tamper-init";
        let mut proof = prover::execute(seed, &test_params()).unwrap();
        proof.init_witnesses[0].block.causal[0] ^= 0xff;
        assert!(verify(seed, &proof).is_err());
    }

    #[test]
    fn tampered_read_block_fails() {
        let seed = b"tamper-read";
        let mut proof = prover::execute(seed, &test_params()).unwrap();
        proof.challenged_steps[0].reads[0].block.data[0] ^= 0xff;
        assert!(verify(seed, &proof).is_err());
    }

    #[test]
    fn entangled_roundtrip() {
        let seed = b"entangle-verify";
        let jitter = [[0xAAu8; 32], [0xBBu8; 32]];
        let proof = prover::execute_entangled(seed, &test_params(), &jitter).unwrap();
        verify(seed, &proof).unwrap();
    }

    #[test]
    fn entangled_wrong_seed_fails() {
        let jitter = [[0xAAu8; 32]];
        let proof = prover::execute_entangled(b"seed-a", &test_params(), &jitter).unwrap();
        assert!(verify(b"seed-b", &proof).is_err());
    }

    #[test]
    fn entangled_tampered_jitter_changes_transcript() {
        let seed = b"tamper-jitter";
        let jitter = [[0xAAu8; 32]];
        let proof = prover::execute_entangled(seed, &test_params(), &jitter).unwrap();
        verify(seed, &proof).unwrap();
        let jitter2 = [[0xBBu8; 32]];
        let proof2 = prover::execute_entangled(seed, &test_params(), &jitter2).unwrap();
        assert_ne!(proof.final_transcript, proof2.final_transcript);
    }

    #[test]
    fn step_id_zero_rejected() {
        let seed = b"c007-test";
        let mut proof = prover::execute(seed, &test_params()).unwrap();
        proof.challenged_steps[0].step_id = 0;
        assert!(verify(seed, &proof).is_err());
    }

    #[test]
    fn step_id_exceeds_k_rejected() {
        let seed = b"c007-oob";
        let mut proof = prover::execute(seed, &test_params()).unwrap();
        proof.challenged_steps[0].step_id = proof.params.total_steps + 1;
        assert!(verify(seed, &proof).is_err());
    }

    #[test]
    fn missing_challenged_step_returns_error() {
        let seed = b"c008-test";
        let mut proof = prover::execute(seed, &test_params()).unwrap();
        if proof.challenged_steps.len() > 1 {
            proof.challenged_steps.pop();
        }
        assert!(verify(seed, &proof).is_err());
    }

    #[test]
    fn constant_jitter_rejected() {
        let seed = b"jitter-const";
        let jitter = [[0xAAu8; 32], [0xAAu8; 32], [0xAAu8; 32]];
        let mut proof = prover::execute_entangled(seed, &test_params(), &jitter).unwrap();
        for ep in &mut proof.entanglement_points {
            ep.1 = [0xAA; 32];
        }
        let result = verify(seed, &proof);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, PosmeError::JitterEntropyInsufficient { .. }));
    }

    #[test]
    fn diverse_jitter_accepted() {
        let seed = b"jitter-diverse";
        let jitter = [[0xAAu8; 32], [0xBBu8; 32]];
        let proof = prover::execute_entangled(seed, &test_params(), &jitter).unwrap();
        verify(seed, &proof).unwrap();
    }

    #[test]
    fn single_jitter_skips_entropy_check() {
        let seed = b"jitter-single";
        let jitter = [[0xAAu8; 32]];
        let proof = prover::execute_entangled(seed, &test_params(), &jitter).unwrap();
        verify(seed, &proof).unwrap();
    }

    fn test_params_depth2() -> PosmeParams {
        PosmeParams {
            recursion_depth: 2,
            ..PosmeParams::test()
        }
    }

    #[test]
    fn recursive_provenance_roundtrip() {
        let seed = b"recursive-verify";
        let proof = prover::execute(seed, &test_params_depth2()).unwrap();
        verify(seed, &proof).unwrap();
    }

    #[test]
    fn recursive_provenance_tampered_writer_fails() {
        let seed = b"tamper-writer";
        let mut proof = prover::execute(seed, &test_params_depth2()).unwrap();
        let tampered = proof
            .challenged_steps
            .iter_mut()
            .find_map(|sp| sp.writers.iter_mut().find(|w| w.step_witness.is_some()));
        if let Some(w) = tampered {
            w.step_witness.as_mut().unwrap().write.new_block.data[0] ^= 0xff;
        }
        assert!(verify(seed, &proof).is_err());
    }

    #[test]
    fn recursive_provenance_wrong_writer_step_id_fails() {
        let seed = b"wrong-writer-id";
        let mut proof = prover::execute(seed, &test_params_depth2()).unwrap();
        let tampered = proof
            .challenged_steps
            .iter_mut()
            .find_map(|sp| sp.writers.iter_mut().find(|w| w.step_witness.is_some()));
        if let Some(w) = tampered {
            w.writer_step_id = w.writer_step_id.wrapping_add(1);
        }
        assert!(verify(seed, &proof).is_err());
    }
}
