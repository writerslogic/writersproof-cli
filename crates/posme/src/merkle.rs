// SPDX-License-Identifier: Apache-2.0

//! Incremental Merkle tree for PoSME arena blocks.
//!
//! 0-indexed flat array. Root at 0, children of `i` at `2i+1`/`2i+2`,
//! leaves at `n-1 .. 2n-2`. Size: `2n - 1`.

use crate::block::{Block, LAMBDA};
use crate::hash::posme_hash;
use subtle::ConstantTimeEq;

/// Leaf hash: single-pass BLAKE3 over the block's 64 contiguous bytes.
pub(crate) fn leaf_hash(block: &Block) -> [u8; LAMBDA] {
    posme_hash(&[block.as_bytes()])
}

fn internal_hash(left: &[u8; LAMBDA], right: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    posme_hash(&[left, right])
}

#[cfg(feature = "prover")]
#[derive(Clone)]
pub struct MerkleTree {
    nodes: Vec<[u8; LAMBDA]>,
    n: u32,
}

#[cfg(feature = "prover")]
impl MerkleTree {
    pub fn build(blocks: &[Block]) -> Self {
        let n = blocks.len() as u32;
        debug_assert!(n.is_power_of_two());
        let size = 2 * n as usize - 1;
        let mut nodes = vec![[0u8; LAMBDA]; size];
        let leaf_base = n as usize - 1;
        for (i, block) in blocks.iter().enumerate() {
            nodes[leaf_base + i] = leaf_hash(block);
        }
        for i in (0..leaf_base).rev() {
            nodes[i] = internal_hash(&nodes[2 * i + 1], &nodes[2 * i + 2]);
        }
        Self { nodes, n }
    }

    pub fn update(&mut self, index: u32, block: &Block) {
        debug_assert!(index < self.n);
        let mut pos = self.n as usize - 1 + index as usize;
        self.nodes[pos] = leaf_hash(block);
        while pos > 0 {
            let parent = (pos - 1) / 2;
            self.nodes[parent] = internal_hash(
                &self.nodes[2 * parent + 1],
                &self.nodes[2 * parent + 2],
            );
            pos = parent;
        }
    }

    pub fn root(&self) -> [u8; LAMBDA] {
        self.nodes[0]
    }

    /// Sibling path, leaf-to-root order.
    pub fn prove(&self, index: u32) -> Vec<[u8; LAMBDA]> {
        debug_assert!(index < self.n);
        let depth = self.n.trailing_zeros() as usize;
        let mut path = Vec::with_capacity(depth);
        let mut pos = self.n as usize - 1 + index as usize;
        for _ in 0..depth {
            let sibling = if pos & 1 == 1 { pos + 1 } else { pos - 1 };
            path.push(self.nodes[sibling]);
            pos = (pos - 1) / 2;
        }
        path
    }
}

/// Verify a Merkle inclusion proof (stateless, no arena needed).
/// Uses 1-indexed position tracking for left/right orientation.
pub(crate) fn verify_path(
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
        current = if pos & 1 == 0 {
            internal_hash(&current, sibling)
        } else {
            internal_hash(sibling, &current)
        };
        pos /= 2;
    }
    current.ct_eq(root).into()
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
        assert!(verify_path(&root_before, 5, &old_block, &path, 16));
        assert!(verify_path(&root_after, 5, &new_block, &path, 16));

        for i in 0..16u32 {
            let p = tree.prove(i);
            assert!(verify_path(&root_after, i, &blocks[i as usize], &p, 16));
        }
    }

    #[test]
    fn verify_rejects_wrong_path_length() {
        let block = Block::zeroed();
        let root = [0u8; LAMBDA];
        let short_path: Vec<[u8; LAMBDA]> = vec![[0u8; LAMBDA]];
        assert!(!verify_path(&root, 0, &block, &short_path, 16));
    }

    #[cfg(feature = "prover")]
    #[test]
    fn tree_size_is_2n_minus_1() {
        let blocks = make_test_blocks(16);
        let tree = MerkleTree::build(&blocks);
        assert_eq!(tree.nodes.len(), 31);
    }
}
