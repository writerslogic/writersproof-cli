// SPDX-License-Identifier: Apache-2.0

//! Arena initialization per draft-condrey-cfrg-posme Section 2.A.

use crate::block::Block;
use crate::hash::{i2osp, posme_hash, DST_CAUSAL, DST_INIT, DST_TRANSCRIPT};
use crate::merkle::MerkleTree;

/// Initialize an N-block arena from a public seed.
///
/// Returns (arena, merkle_tree, root_0, T_0).
///
/// Block 0: data = H(DST_INIT || seed || 0)
/// Block i: data = H(DST_INIT || seed || i || A[i-1].data || A[floor(i/2)].data)
/// All:     causal = H(DST_CAUSAL || seed || i)
pub(crate) fn initialize(seed: &[u8], n: u32) -> (Vec<Block>, MerkleTree, [u8; 32], [u8; 32]) {
    let mut blocks = vec![Block::zeroed(); n as usize];

    blocks[0].data = posme_hash(&[DST_INIT, seed, &i2osp(0)]);
    blocks[0].causal = posme_hash(&[DST_CAUSAL, seed, &i2osp(0)]);

    for i in 1..n as usize {
        let prev = blocks[i - 1].data;
        let skip = blocks[i / 2].data;
        blocks[i].data = posme_hash(&[DST_INIT, seed, &i2osp(i as u32), &prev, &skip]);
        blocks[i].causal = posme_hash(&[DST_CAUSAL, seed, &i2osp(i as u32)]);
    }

    let tree = MerkleTree::build(&blocks);
    let root_0 = tree.root();
    let t_0 = posme_hash(&[DST_TRANSCRIPT, seed, &root_0]);

    (blocks, tree, root_0, t_0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_deterministic() {
        let (_, _, root_a, t_a) = initialize(b"seed-1", 1024);
        let (_, _, root_b, t_b) = initialize(b"seed-1", 1024);
        assert_eq!(root_a, root_b);
        assert_eq!(t_a, t_b);
    }

    #[test]
    fn init_different_seeds_differ() {
        let (_, _, root_a, _) = initialize(b"seed-1", 1024);
        let (_, _, root_b, _) = initialize(b"seed-2", 1024);
        assert_ne!(root_a, root_b);
    }

    #[test]
    fn init_skip_link_structure() {
        let (blocks, _, _, _) = initialize(b"test", 1024);
        // Block 0 has no skip-link dependency.
        let expected_0 = posme_hash(&[DST_INIT, b"test", &i2osp(0)]);
        assert_eq!(blocks[0].data, expected_0);
        // Block 1 depends on block 0 (prev) and block 0 (skip = floor(1/2)).
        let expected_1 = posme_hash(&[
            DST_INIT,
            b"test",
            &i2osp(1),
            &blocks[0].data,
            &blocks[0].data,
        ]);
        assert_eq!(blocks[1].data, expected_1);
    }
}
