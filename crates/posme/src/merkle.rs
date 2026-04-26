// SPDX-License-Identifier: Apache-2.0

//! Incremental Merkle tree for PoSME arena blocks.
//!
//! 1-indexed binary tree stored in a flat Vec. Supports O(log N) single-leaf
//! updates (critical for the step function which writes one block per step).
//!
//! Leaf hash: BLAKE3(block.data || block.causal)
//! Internal:  BLAKE3(left_hash || right_hash)

use crate::block::{Block, LAMBDA};
use crate::hash::posme_hash;
use subtle::ConstantTimeEq;

/// Compute the leaf hash for a block.
pub fn leaf_hash(block: &Block) -> [u8; LAMBDA] {
    posme_hash(&[&block.data, &block.causal])
}

/// Compute an internal node hash from two children.
fn internal_hash(left: &[u8; LAMBDA], right: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    posme_hash(&[left, right])
}

/// Incremental Merkle tree over N leaves (N must be a power of 2).
///
/// Stored as a 1-indexed array: nodes[1] = root, nodes[n..2n-1] = leaves.
#[cfg(feature = "prover")]
#[derive(Clone)]
pub struct MerkleTree {
    nodes: Vec<[u8; LAMBDA]>,
    n: u32,
}

#[cfg(feature = "prover")]
impl MerkleTree {
    /// Build a Merkle tree from an arena of blocks.
    pub fn build(blocks: &[Block]) -> Self {
        let n = blocks.len() as u32;
        debug_assert!(n.is_power_of_two());
        // 2*n nodes: index 0 unused, 1..n-1 = internal, n..2n-1 = leaves.
        let mut nodes = vec![[0u8; LAMBDA]; 2 * n as usize];

        // Set leaves.
        for (i, block) in blocks.iter().enumerate() {
            nodes[n as usize + i] = leaf_hash(block);
        }

        // Build internal nodes bottom-up.
        for i in (1..n as usize).rev() {
            nodes[i] = internal_hash(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self { nodes, n }
    }

    /// Update a single leaf and propagate changes to the root. O(log N).
    pub fn update(&mut self, index: u32, block: &Block) {
        debug_assert!(index < self.n);
        let mut pos = self.n as usize + index as usize;
        self.nodes[pos] = leaf_hash(block);
        pos /= 2;
        while pos >= 1 {
            self.nodes[pos] = internal_hash(&self.nodes[2 * pos], &self.nodes[2 * pos + 1]);
            pos /= 2;
        }
    }

    /// Return the current root hash.
    pub fn root(&self) -> [u8; LAMBDA] {
        self.nodes[1]
    }

    /// Generate a sibling path (Merkle proof) for the leaf at `index`.
    /// Path is ordered leaf-to-root.
    pub fn prove(&self, index: u32) -> Vec<[u8; LAMBDA]> {
        debug_assert!(index < self.n);
        let depth = self.n.trailing_zeros() as usize;
        let mut path = Vec::with_capacity(depth);
        let mut pos = self.n as usize + index as usize;
        for _ in 0..depth {
            let sibling = pos ^ 1;
            path.push(self.nodes[sibling]);
            pos /= 2;
        }
        path
    }
}

/// Verify a Merkle inclusion proof without allocating an arena.
///
/// `root`: expected root hash.
/// `index`: leaf index (0-based).
/// `block`: the block at that leaf.
/// `path`: sibling hashes, leaf-to-root order.
/// `n`: total number of leaves (power of 2).
pub fn verify_path(
    root: &[u8; LAMBDA],
    index: u32,
    block: &Block,
    path: &[[u8; LAMBDA]],
    n: u32,
) -> bool {
    let expected_depth = n.trailing_zeros() as usize;
    if path.len() != expected_depth {
        return false;
    }
    let mut current = leaf_hash(block);
    let mut pos = n + index;
    for sibling in path {
        current = if pos.is_multiple_of(2) {
            internal_hash(&current, sibling)
        } else {
            internal_hash(sibling, &current)
        };
        pos /= 2;
    }
    current.ct_eq(root).into()
}

/// Verify that a single-leaf update transforms root_before into root_after.
///
/// Uses the Merkle path (which is the same for old and new block at the same index)
/// to verify both roots without arena allocation.
pub fn verify_update(
    root_before: &[u8; LAMBDA],
    root_after: &[u8; LAMBDA],
    index: u32,
    old_block: &Block,
    new_block: &Block,
    path: &[[u8; LAMBDA]],
    n: u32,
) -> bool {
    verify_path(root_before, index, old_block, path, n)
        && verify_path(root_after, index, new_block, path, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "prover")]
    use crate::hash::{posme_hash, DST_INIT, DST_CAUSAL, i2osp};

    #[cfg(feature = "prover")]
    fn make_test_blocks(n: u32) -> Vec<Block> {
        let seed = b"test-seed";
        let mut blocks = vec![Block::zeroed(); n as usize];
        blocks[0].data = posme_hash(&[DST_INIT, seed.as_slice(), &i2osp(0)]);
        blocks[0].causal = posme_hash(&[DST_CAUSAL, seed.as_slice(), &i2osp(0)]);
        for i in 1..n as usize {
            let prev = blocks[i - 1].data;
            let skip = blocks[i / 2].data;
            blocks[i].data = posme_hash(&[DST_INIT, seed.as_slice(), &i2osp(i as u32), &prev, &skip]);
            blocks[i].causal = posme_hash(&[DST_CAUSAL, seed.as_slice(), &i2osp(i as u32)]);
        }
        blocks
    }

    #[cfg(feature = "prover")]
    #[test]
    fn build_and_root_deterministic() {
        let blocks = make_test_blocks(16);
        let t1 = MerkleTree::build(&blocks);
        let t2 = MerkleTree::build(&blocks);
        assert_eq!(t1.root(), t2.root());
    }

    #[cfg(feature = "prover")]
    #[test]
    fn prove_and_verify() {
        let blocks = make_test_blocks(16);
        let tree = MerkleTree::build(&blocks);
        let root = tree.root();
        for i in 0..16u32 {
            let path = tree.prove(i);
            assert!(verify_path(&root, i, &blocks[i as usize], &path, 16));
        }
    }

    #[cfg(feature = "prover")]
    #[test]
    fn verify_rejects_wrong_block() {
        let blocks = make_test_blocks(16);
        let tree = MerkleTree::build(&blocks);
        let root = tree.root();
        let path = tree.prove(0);
        let wrong = Block { data: [0xff; LAMBDA], causal: [0; LAMBDA] };
        assert!(!verify_path(&root, 0, &wrong, &path, 16));
    }

    #[cfg(feature = "prover")]
    #[test]
    fn update_single_leaf() {
        let mut blocks = make_test_blocks(16);
        let mut tree = MerkleTree::build(&blocks);
        let root_before = tree.root();

        let new_block = Block { data: [0xab; LAMBDA], causal: [0xcd; LAMBDA] };
        let old_block = blocks[5];
        let path = tree.prove(5);

        tree.update(5, &new_block);
        blocks[5] = new_block;
        let root_after = tree.root();

        assert_ne!(root_before, root_after);
        assert!(verify_update(&root_before, &root_after, 5, &old_block, &new_block, &path, 16));

        // Verify all other paths still valid.
        for i in 0..16u32 {
            let p = tree.prove(i);
            assert!(verify_path(&root_after, i, &blocks[i as usize], &p, 16));
        }
    }

    #[test]
    fn verify_rejects_wrong_path_length() {
        let block = Block::zeroed();
        let root = [0u8; LAMBDA];
        let short_path: Vec<[u8; LAMBDA]> = vec![[0u8; LAMBDA]]; // depth 1 for n=16 (need 4)
        assert!(!verify_path(&root, 0, &block, &short_path, 16));
    }
}
