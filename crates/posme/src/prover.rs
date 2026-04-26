// SPDX-License-Identifier: Apache-2.0

//! PoSME proof generation: execute K steps, derive challenges, build proof.
//!
//! Two-pass strategy: the execution pass stores per-step roots (32 bytes each)
//! and builds a root chain commitment. Dead allocations (arena, tree, roots) are
//! freed between passes. Challenged steps are replayed to regenerate witnesses.

use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use crate::block::LAMBDA;
use crate::error::Result;
use crate::hash::{derive_challenges, i2osp, posme_hash};
use crate::init::initialize;
use crate::merkle::MerkleTree;
use crate::params::PosmeParams;
use crate::proof::*;
use crate::step::{posme_step, StepLog};

/// Root chain Merkle tree: commits to all K+1 arena roots.
struct RootChain {
    nodes: Vec<[u8; LAMBDA]>,
    n: usize,
}

impl RootChain {
    fn build(roots: &[[u8; LAMBDA]]) -> Self {
        let n = roots.len().next_power_of_two();
        let mut nodes = vec![[0u8; LAMBDA]; 2 * n];
        for (i, root) in roots.iter().enumerate() {
            nodes[n + i] = *root;
        }
        for i in (1..n).rev() {
            nodes[i] = posme_hash(&[&nodes[2 * i], &nodes[2 * i + 1]]);
        }
        Self { nodes, n }
    }

    fn root(&self) -> [u8; LAMBDA] {
        self.nodes[1]
    }

    fn prove(&self, index: usize) -> Vec<[u8; LAMBDA]> {
        let depth = (self.n as u32).trailing_zeros() as usize;
        let mut path = Vec::with_capacity(depth);
        let mut pos = self.n + index;
        for _ in 0..depth {
            path.push(self.nodes[pos ^ 1]);
            pos /= 2;
        }
        path
    }
}

/// Track which step last wrote each block.
struct WriteIndex {
    last_writer: Vec<u32>,
}

impl WriteIndex {
    fn new(n: u32) -> Self {
        Self { last_writer: vec![0; n as usize] }
    }

    fn record(&mut self, addr: u32, step: u32) {
        self.last_writer[addr as usize] = step;
    }

    fn last_writer_of(&self, addr: u32) -> u32 {
        self.last_writer[addr as usize]
    }
}

struct ProofBuildCtx<'a> {
    root_chain: &'a RootChain,
    write_index: &'a WriteIndex,
    init_tree: &'a MerkleTree,
}

fn build_step_proof(
    log: &StepLog,
    tree_before: &MerkleTree,
    cursor_in: [u8; LAMBDA],
    ctx: &ProofBuildCtx<'_>,
) -> StepProof {
    let rc_path_before = ctx.root_chain.prove(log.step_id as usize - 1);
    let rc_path_after = ctx.root_chain.prove(log.step_id as usize);

    let reads: Vec<ReadWitness> = log.read_addrs.iter().zip(&log.read_blocks).map(|(&addr, &block)| {
        ReadWitness {
            address: addr,
            block,
            merkle_path: tree_before.prove(addr),
        }
    }).collect();

    let write = WriteWitness {
        address: log.write_addr,
        old_block: log.old_block,
        new_block: log.new_block,
        merkle_path: tree_before.prove(log.write_addr),
    };

    let writers: Vec<WriterProof> = log.read_addrs.iter().map(|&addr| {
        let ws = ctx.write_index.last_writer_of(addr);
        if ws == 0 {
            WriterProof {
                proof_type: 0,
                writer_step_id: 0,
                step_witness: None,
                init_merkle_path: Some(ctx.init_tree.prove(addr)),
            }
        } else {
            WriterProof {
                proof_type: 1,
                writer_step_id: ws,
                step_witness: None,
                init_merkle_path: None,
            }
        }
    }).collect();

    StepProof {
        step_id: log.step_id,
        cursor_in,
        cursor_out: log.cursor,
        root_before: log.root_before,
        root_after: log.root_after,
        root_chain_paths: (rc_path_before, rc_path_after),
        reads,
        write,
        writers,
    }
}

/// Generate init block witnesses for seed binding.
/// Uses Fiat-Shamir to select INIT_WITNESS_COUNT block indices deterministically.
fn generate_init_witnesses(
    seed: &[u8],
    init_tree: &MerkleTree,
    arena: &[crate::block::Block],
    n: u32,
) -> Vec<InitWitness> {
    let root = init_tree.root();
    let sigma = posme_hash(&[b"PoSME-init-witness-v1", seed, &root]);
    let mut witnesses = Vec::with_capacity(INIT_WITNESS_COUNT);
    let mut counter = 0u32;
    while witnesses.len() < INIT_WITNESS_COUNT {
        let h = posme_hash(&[&sigma, &i2osp(counter)]);
        let idx = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % n;
        counter += 1;
        if witnesses.iter().any(|w: &InitWitness| w.index == idx) {
            continue;
        }
        witnesses.push(InitWitness {
            index: idx,
            block: arena[idx as usize],
            merkle_path: init_tree.prove(idx),
        });
    }
    witnesses
}

/// Replay from init, building StepProofs only for the specified target steps.
fn replay_for_writer_proofs(
    seed: &[u8],
    params: &PosmeParams,
    root_chain: &RootChain,
    targets: &BTreeSet<u32>,
    entangle: Option<(&[[u8; 32]], usize)>,
) -> HashMap<u32, StepProof> {
    if targets.is_empty() {
        return HashMap::new();
    }

    let n = params.arena_blocks;
    let d = params.reads_per_step;
    let max_target = *targets.iter().next_back().unwrap();

    let (mut arena, mut tree, _, mut transcript) = initialize(seed, n);
    let init_tree = MerkleTree::build(&arena);
    let mut wi = WriteIndex::new(n);
    let mut results = HashMap::new();
    let mut jitter_idx = 0usize;

    for step in 1..=max_target {
        let is_target = targets.contains(&step);
        let tree_before = if is_target { Some(tree.clone()) } else { None };
        let cursor_in = transcript;

        let log = posme_step(&mut arena, &mut tree, &transcript, step, d);
        transcript = log.transcript;

        if let Some((samples, interval)) = entangle {
            if interval > 0
                && (step as usize).is_multiple_of(interval)
                && jitter_idx < samples.len()
            {
                transcript =
                    posme_hash(&[ENTANGLE_DST, &transcript, &samples[jitter_idx]]);
                jitter_idx += 1;
            }
        }

        wi.record(log.write_addr, step);

        if let Some(tb) = tree_before {
            let ctx = ProofBuildCtx {
                root_chain,
                write_index: &wi,
                init_tree: &init_tree,
            };
            let sp = build_step_proof(&log, &tb, cursor_in, &ctx);
            results.insert(step, sp);
        }
    }

    results
}

/// Attach recursive writer proofs to step proofs, iterating depth levels.
///
/// R=1 means writers are identified (already done). Each additional level
/// replays execution to build StepProofs for unproved writer steps.
fn attach_recursive_writers(
    challenged_steps: &mut [StepProof],
    seed: &[u8],
    params: &PosmeParams,
    root_chain: &RootChain,
    entangle: Option<(&[[u8; 32]], usize)>,
) {
    for _ in 1..params.recursion_depth {
        // Collect all writer step IDs that still need proofs.
        let mut needed = BTreeSet::new();
        for sp in challenged_steps.iter() {
            collect_unproved_writers(sp, &mut needed);
        }
        if needed.is_empty() {
            break;
        }

        let mut writer_proofs =
            replay_for_writer_proofs(seed, params, root_chain, &needed, entangle);

        for sp in challenged_steps.iter_mut() {
            attach_writer_proofs(sp, &mut writer_proofs);
        }
    }
}

/// Recursively collect writer step IDs that have proof_type=1 but no step_witness.
fn collect_unproved_writers(sp: &StepProof, out: &mut BTreeSet<u32>) {
    for w in &sp.writers {
        if w.proof_type == 1 && w.step_witness.is_none() {
            out.insert(w.writer_step_id);
        }
        if let Some(ref witness) = w.step_witness {
            collect_unproved_writers(witness, out);
        }
    }
}

/// Recursively attach writer proofs from the map into the step proof tree.
fn attach_writer_proofs(sp: &mut StepProof, proofs: &mut HashMap<u32, StepProof>) {
    for w in sp.writers.iter_mut() {
        if w.proof_type == 1 && w.step_witness.is_none() {
            if let Some(wp) = proofs.get(&w.writer_step_id) {
                w.step_witness = Some(Box::new(wp.clone()));
            }
        }
        if let Some(ref mut witness) = w.step_witness {
            attach_writer_proofs(witness, proofs);
        }
    }
}

const ENTANGLE_DST: &[u8] = b"PoSME-entangle-v1";

/// Optional jitter entanglement configuration for `execute_inner`.
struct EntangleCtx<'a> {
    samples: &'a [[u8; 32]],
    interval: usize,
    idx: usize,
    points: Vec<(u32, [u8; 32])>,
}

impl<'a> EntangleCtx<'a> {
    fn new(samples: &'a [[u8; 32]], interval: usize) -> Self {
        Self { samples, interval, idx: 0, points: Vec::new() }
    }

    /// Mix jitter into the transcript at injection points, recording the point.
    fn maybe_inject(&mut self, step: u32, transcript: &mut [u8; LAMBDA]) {
        if self.interval > 0
            && (step as usize).is_multiple_of(self.interval)
            && self.idx < self.samples.len()
        {
            let jh = self.samples[self.idx];
            *transcript = posme_hash(&[ENTANGLE_DST, transcript.as_slice(), &jh]);
            self.points.push((step, jh));
            self.idx += 1;
        }
    }

    /// Mix jitter into the transcript at injection points without recording.
    fn maybe_inject_silent(&mut self, step: u32, transcript: &mut [u8; LAMBDA]) {
        if self.interval > 0
            && (step as usize).is_multiple_of(self.interval)
            && self.idx < self.samples.len()
        {
            let jh = self.samples[self.idx];
            *transcript = posme_hash(&[ENTANGLE_DST, transcript.as_slice(), &jh]);
            self.idx += 1;
        }
    }

    fn as_replay_arg(&self) -> Option<(&'a [[u8; 32]], usize)> {
        Some((self.samples, self.interval))
    }
}

/// Unified proof generation for both standard and entangled modes.
fn execute_inner(
    seed: &[u8],
    params: &PosmeParams,
    mut entangle: Option<EntangleCtx<'_>>,
) -> Result<PosmeProof> {
    let n = params.arena_blocks;
    let k = params.total_steps;
    let d = params.reads_per_step;

    // Phase 1: Initialize arena and snapshot the init tree.
    let (mut arena, mut tree, root_0, t_0) = initialize(seed, n);
    let init_tree = MerkleTree::build(&arena);
    let init_witnesses = generate_init_witnesses(seed, &init_tree, &arena, n);
    drop(init_tree);

    // Phase 2: Execute K steps, storing only roots.
    let mut transcript = t_0;
    let root_cap = (k as usize).checked_add(1).ok_or_else(|| {
        crate::error::PosmeError::InvalidParams("total_steps overflow in root count".into())
    })?;
    let mut roots: Vec<[u8; LAMBDA]> = Vec::with_capacity(root_cap);
    roots.push(root_0);

    let start = Instant::now();
    for t in 1..=k {
        let log = posme_step(&mut arena, &mut tree, &transcript, t, d);
        transcript = log.transcript;
        if let Some(ref mut ent) = entangle {
            ent.maybe_inject(t, &mut transcript);
        }
        roots.push(log.root_after);
    }
    let elapsed = start.elapsed();
    let final_transcript = transcript;
    drop(arena);
    drop(tree);

    // Phase 3: Build root chain commitment.
    let root_chain = RootChain::build(&roots);
    drop(roots);
    let root_chain_commitment = root_chain.root();

    // Phase 4: Derive Fiat-Shamir challenges.
    let challenges = derive_challenges(&final_transcript, &root_chain_commitment, params);

    // Phase 5: Replay challenged steps to build proofs.
    let mut sorted_challenges: Vec<(usize, u32)> =
        challenges.iter().enumerate().map(|(i, &s)| (i, s)).collect();
    sorted_challenges.sort_by_key(|&(_, step)| step);

    let mut step_proofs: Vec<(usize, StepProof)> = Vec::with_capacity(challenges.len());
    let (mut replay_arena, mut replay_tree, _, mut replay_t) = initialize(seed, n);
    let init_tree = MerkleTree::build(&replay_arena);
    let mut replay_wi = WriteIndex::new(n);
    let mut current_step = 0u32;
    let mut replay_ent = entangle.as_ref().map(|e| EntangleCtx::new(e.samples, e.interval));

    for &(orig_idx, target_step) in &sorted_challenges {
        while current_step < target_step - 1 {
            current_step += 1;
            let log = posme_step(
                &mut replay_arena, &mut replay_tree, &replay_t, current_step, d,
            );
            replay_t = log.transcript;
            if let Some(ref mut re) = replay_ent {
                re.maybe_inject_silent(current_step, &mut replay_t);
            }
            replay_wi.record(log.write_addr, current_step);
        }

        let tree_before = replay_tree.clone();
        let cursor_in = replay_t;

        current_step += 1;
        debug_assert_eq!(current_step, target_step);
        let log = posme_step(
            &mut replay_arena, &mut replay_tree, &replay_t, current_step, d,
        );
        replay_t = log.transcript;
        if let Some(ref mut re) = replay_ent {
            re.maybe_inject_silent(current_step, &mut replay_t);
        }
        replay_wi.record(log.write_addr, current_step);

        let build_ctx = ProofBuildCtx {
            root_chain: &root_chain,
            write_index: &replay_wi,
            init_tree: &init_tree,
        };
        let sp = build_step_proof(&log, &tree_before, cursor_in, &build_ctx);
        step_proofs.push((orig_idx, sp));
    }

    // Restore original challenge order.
    step_proofs.sort_by_key(|&(orig_idx, _)| orig_idx);
    let mut challenged_steps: Vec<StepProof> =
        step_proofs.into_iter().map(|(_, sp)| sp).collect();

    // Phase 6: Recursive provenance — attach writer step proofs.
    let entangle_arg = entangle.as_ref().and_then(|e| e.as_replay_arg());
    attach_recursive_writers(&mut challenged_steps, seed, params, &root_chain, entangle_arg);

    let root_0_path = root_chain.prove(0);

    let (proof_algorithm, entanglement_points) = match entangle {
        Some(ent) => (PROOF_ALGORITHM_POSME_ENTANGLED, ent.points),
        None => (PROOF_ALGORITHM_POSME, Vec::new()),
    };

    Ok(PosmeProof {
        params: *params,
        final_transcript,
        root_chain_commitment,
        root_0,
        root_0_path,
        init_witnesses,
        challenged_steps,
        claimed_duration: elapsed,
        proof_algorithm,
        entanglement_points,
    })
}

/// Execute the full PoSME computation and generate a proof.
///
/// Two-pass strategy:
/// 1. Execute all K steps, storing only per-step metadata (transcript + write_addr).
/// 2. Sort challenged steps, replay from init up to each one to get correct Merkle paths.
pub fn execute(seed: &[u8], params: &PosmeParams) -> Result<PosmeProof> {
    params.validate()?;
    execute_inner(seed, params, None)
}

/// Execute PoSME with jitter entanglement (algorithm 31).
///
/// At evenly-spaced intervals during execution, a jitter sample hash is mixed
/// into the transcript chain: `T_t = H("PoSME-entangle-v1" || T_t || jitter_hash)`.
/// The injection points and hashes are recorded in the proof for verification.
///
/// `jitter_samples`: one or more 32-byte jitter hashes collected during the session.
/// Injection occurs every `K / jitter_samples.len()` steps.
pub fn execute_entangled(
    seed: &[u8],
    params: &PosmeParams,
    jitter_samples: &[[u8; 32]],
) -> Result<PosmeProof> {
    if jitter_samples.is_empty() {
        return execute(seed, params);
    }
    params.validate()?;
    let k = params.total_steps;
    let interval = (k as usize) / jitter_samples.len();
    if interval == 0 {
        return Err(crate::error::PosmeError::InvalidParams(format!(
            "too many jitter samples ({}) for total_steps ({}); need at most {} samples",
            jitter_samples.len(),
            k,
            k
        )));
    }
    execute_inner(seed, params, Some(EntangleCtx::new(jitter_samples, interval)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> PosmeParams {
        PosmeParams::test()
    }

    #[test]
    fn execute_produces_proof() {
        let proof = execute(b"test-seed", &test_params()).unwrap();
        assert_eq!(proof.params, test_params());
        assert_eq!(proof.challenged_steps.len(), test_params().challenges as usize);
        assert_eq!(proof.proof_algorithm, PROOF_ALGORITHM_POSME);
        assert_eq!(proof.init_witnesses.len(), INIT_WITNESS_COUNT);
    }

    #[test]
    fn execute_deterministic() {
        let p1 = execute(b"det-seed", &test_params()).unwrap();
        let p2 = execute(b"det-seed", &test_params()).unwrap();
        assert_eq!(p1.final_transcript, p2.final_transcript);
        assert_eq!(p1.root_chain_commitment, p2.root_chain_commitment);
        assert_eq!(p1.init_witnesses.len(), p2.init_witnesses.len());
        for (a, b) in p1.init_witnesses.iter().zip(&p2.init_witnesses) {
            assert_eq!(a.index, b.index);
            assert_eq!(a.block, b.block);
        }
    }

    #[test]
    fn execute_different_seeds_differ() {
        let p1 = execute(b"seed-a", &test_params()).unwrap();
        let p2 = execute(b"seed-b", &test_params()).unwrap();
        assert_ne!(p1.final_transcript, p2.final_transcript);
    }

    #[test]
    fn challenges_are_unique() {
        let proof = execute(b"test", &test_params()).unwrap();
        let step_ids: Vec<u32> = proof.challenged_steps.iter().map(|s| s.step_id).collect();
        let mut deduped = step_ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(step_ids.len(), deduped.len());
    }

    #[test]
    fn challenges_in_range() {
        let params = test_params();
        let proof = execute(b"test", &params).unwrap();
        for sp in &proof.challenged_steps {
            assert!(sp.step_id >= 1 && sp.step_id <= params.total_steps);
        }
    }

    #[test]
    fn init_witnesses_in_range() {
        let params = test_params();
        let proof = execute(b"test", &params).unwrap();
        for w in &proof.init_witnesses {
            assert!(w.index < params.arena_blocks);
        }
    }

    #[test]
    fn entangled_produces_proof() {
        let jitter = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]];
        let proof = execute_entangled(b"entangle-test", &test_params(), &jitter).unwrap();
        assert_eq!(proof.proof_algorithm, PROOF_ALGORITHM_POSME_ENTANGLED);
        assert_eq!(proof.entanglement_points.len(), 3);
    }

    #[test]
    fn entangled_differs_from_standard() {
        let seed = b"compare";
        let standard = execute(seed, &test_params()).unwrap();
        let jitter = [[0x11u8; 32]];
        let entangled = execute_entangled(seed, &test_params(), &jitter).unwrap();
        assert_ne!(standard.final_transcript, entangled.final_transcript);
    }

    #[test]
    fn entangled_deterministic() {
        let jitter = [[0x42u8; 32], [0x43u8; 32]];
        let p1 = execute_entangled(b"det", &test_params(), &jitter).unwrap();
        let p2 = execute_entangled(b"det", &test_params(), &jitter).unwrap();
        assert_eq!(p1.final_transcript, p2.final_transcript);
        assert_eq!(p1.entanglement_points, p2.entanglement_points);
    }

    #[test]
    fn empty_jitter_falls_back_to_standard() {
        let standard = execute(b"fb", &test_params()).unwrap();
        let entangled = execute_entangled(b"fb", &test_params(), &[]).unwrap();
        assert_eq!(standard.final_transcript, entangled.final_transcript);
        assert_eq!(entangled.proof_algorithm, PROOF_ALGORITHM_POSME);
    }

    fn test_params_depth2() -> PosmeParams {
        PosmeParams {
            recursion_depth: 2,
            ..PosmeParams::test()
        }
    }

    #[test]
    fn recursive_provenance_depth2_has_writer_witnesses() {
        let proof = execute(b"depth2-test", &test_params_depth2()).unwrap();
        // At depth 2, at least some writers with proof_type=1 should have step_witness.
        let has_witness = proof.challenged_steps.iter().any(|sp| {
            sp.writers
                .iter()
                .any(|w| w.proof_type == 1 && w.step_witness.is_some())
        });
        assert!(has_witness, "depth=2 should produce writer step witnesses");
    }

    #[test]
    fn recursive_provenance_deterministic() {
        let params = test_params_depth2();
        let p1 = execute(b"det-depth2", &params).unwrap();
        let p2 = execute(b"det-depth2", &params).unwrap();
        assert_eq!(p1.final_transcript, p2.final_transcript);
        for (a, b) in p1.challenged_steps.iter().zip(&p2.challenged_steps) {
            for (wa, wb) in a.writers.iter().zip(&b.writers) {
                assert_eq!(wa.proof_type, wb.proof_type);
                assert_eq!(wa.writer_step_id, wb.writer_step_id);
                assert_eq!(wa.step_witness.is_some(), wb.step_witness.is_some());
            }
        }
    }

    #[test]
    fn too_many_jitter_samples_rejected() {
        let params = test_params();
        // More samples than total_steps → interval would be 0.
        let samples: Vec<[u8; 32]> = (0..params.total_steps + 1)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                h
            })
            .collect();
        let result = execute_entangled(b"too-many", &params, &samples);
        assert!(result.is_err());
    }
}
