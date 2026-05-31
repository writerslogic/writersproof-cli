// SPDX-License-Identifier: Apache-2.0

//! Single PoSME step function per draft-condrey-cfrg-posme Section 2.B.

use crate::block::{Block, LAMBDA};
use crate::hash::{addr_from, i2osp, posme_hash};
use crate::merkle::MerkleTree;

pub(crate) const MAX_READS: usize = 8;

/// Full step log with stack-allocated read arrays (no heap allocation).
pub(crate) struct StepLog {
    pub step_id: u32,
    pub read_addrs: [u32; MAX_READS],
    pub read_blocks: [Block; MAX_READS],
    pub read_count: u8,
    pub write_addr: u32,
    pub old_block: Block,
    pub new_block: Block,
    pub cursor: [u8; LAMBDA],
    pub root_before: [u8; LAMBDA],
    pub root_after: [u8; LAMBDA],
    pub transcript: [u8; LAMBDA],
}

impl StepLog {
    #[inline]
    pub fn read_addrs(&self) -> &[u32] {
        &self.read_addrs[..self.read_count as usize]
    }

    #[inline]
    pub fn read_blocks(&self) -> &[Block] {
        &self.read_blocks[..self.read_count as usize]
    }
}

/// Lightweight step result for the execution pass (no read tracking).
pub(crate) struct StepResult {
    pub write_addr: u32,
    pub root_after: [u8; LAMBDA],
    pub transcript: [u8; LAMBDA],
}

/// Zero-allocation step: mutates arena/tree, returns only what the execution
/// pass needs. Skips read recording, root_before, and cursor capture.
#[inline(never)]
pub(crate) fn posme_step_light(
    arena: &mut [Block],
    tree: &mut MerkleTree,
    t_prev: &[u8; LAMBDA],
    t: u32,
    d: u8,
) -> StepResult {
    let n = arena.len() as u32;
    let mut cursor = *t_prev;

    for j in 0..d {
        let a = addr_from(&cursor, u32::from(j), n);
        let val = arena[a as usize];
        cursor = posme_hash(&[&cursor, &val.data, &val.causal]);
    }

    let w = addr_from(&cursor, u32::from(d), n);
    let old = arena[w as usize];
    let new_data = posme_hash(&[&old.data, &cursor, &old.causal]);
    let new_causal = posme_hash(&[&old.causal, &cursor, &i2osp(t)]);
    let new_block = Block { data: new_data, causal: new_causal };
    arena[w as usize] = new_block;
    tree.update(w, &new_block);
    let root_after = tree.root();
    let transcript = posme_hash(&[t_prev, &i2osp(t), &cursor, &root_after]);

    StepResult { write_addr: w, root_after, transcript }
}

/// Full step with witness capture. Stack-allocated arrays, no heap allocation.
#[inline(never)]
pub(crate) fn posme_step(
    arena: &mut [Block],
    tree: &mut MerkleTree,
    t_prev: &[u8; LAMBDA],
    t: u32,
    d: u8,
) -> StepLog {
    let n = arena.len() as u32;
    debug_assert!((d as usize) <= MAX_READS);
    let mut cursor = *t_prev;
    let mut read_addrs = [0u32; MAX_READS];
    let mut read_blocks = [Block::zeroed(); MAX_READS];

    for j in 0..d {
        let a = addr_from(&cursor, u32::from(j), n);
        read_addrs[j as usize] = a;
        let val = arena[a as usize];
        read_blocks[j as usize] = val;
        cursor = posme_hash(&[&cursor, &val.data, &val.causal]);
    }

    let root_before = tree.root();
    let w = addr_from(&cursor, u32::from(d), n);
    let old_block = arena[w as usize];
    let new_data = posme_hash(&[&old_block.data, &cursor, &old_block.causal]);
    let new_causal = posme_hash(&[&old_block.causal, &cursor, &i2osp(t)]);
    let new_block = Block { data: new_data, causal: new_causal };
    arena[w as usize] = new_block;
    tree.update(w, &new_block);
    let root_after = tree.root();
    let transcript = posme_hash(&[t_prev, &i2osp(t), &cursor, &root_after]);

    StepLog {
        step_id: t,
        read_addrs,
        read_blocks,
        read_count: d,
        write_addr: w,
        old_block,
        new_block,
        cursor,
        root_before,
        root_after,
        transcript,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::initialize;

    #[test]
    fn step_mutates_arena() {
        let (mut arena, mut tree, _, t_0) = initialize(b"test", 1024);
        let log = posme_step(&mut arena, &mut tree, &t_0, 1, 8);
        assert_eq!(arena[log.write_addr as usize], log.new_block);
        assert_ne!(log.old_block, log.new_block);
    }

    #[test]
    fn step_advances_transcript() {
        let (mut arena, mut tree, _, t_0) = initialize(b"test", 1024);
        let log = posme_step(&mut arena, &mut tree, &t_0, 1, 8);
        assert_ne!(t_0, log.transcript);
    }

    #[test]
    fn step_deterministic() {
        let (mut a1, mut t1, _, t_0a) = initialize(b"det", 1024);
        let (mut a2, mut t2, _, t_0b) = initialize(b"det", 1024);
        let log1 = posme_step(&mut a1, &mut t1, &t_0a, 1, 8);
        let log2 = posme_step(&mut a2, &mut t2, &t_0b, 1, 8);
        assert_eq!(log1.transcript, log2.transcript);
        assert_eq!(log1.write_addr, log2.write_addr);
        assert_eq!(log1.read_addrs(), log2.read_addrs());
    }

    #[test]
    fn step_root_changes() {
        let (mut arena, mut tree, _, t_0) = initialize(b"test", 1024);
        let log = posme_step(&mut arena, &mut tree, &t_0, 1, 8);
        assert_ne!(log.root_before, log.root_after);
    }

    #[test]
    fn step_transcript_includes_root() {
        let (mut arena, mut tree, _, t_0) = initialize(b"test", 1024);
        let log = posme_step(&mut arena, &mut tree, &t_0, 1, 8);
        let expected = posme_hash(&[&t_0, &i2osp(1), &log.cursor, &log.root_after]);
        assert_eq!(log.transcript, expected);
    }

    #[test]
    fn light_step_matches_full_step() {
        let (mut a1, mut t1, _, t_0) = initialize(b"match", 1024);
        let (mut a2, mut t2, _, _) = initialize(b"match", 1024);
        let full = posme_step(&mut a1, &mut t1, &t_0, 1, 8);
        let light = posme_step_light(&mut a2, &mut t2, &t_0, 1, 8);
        assert_eq!(full.write_addr, light.write_addr);
        assert_eq!(full.root_after, light.root_after);
        assert_eq!(full.transcript, light.transcript);
    }
}
