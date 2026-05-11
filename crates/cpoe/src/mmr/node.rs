// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::mmr::errors::MmrError;
use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = 32;
pub const NODE_SIZE: usize = 41;

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

const LEAF_DST: &[u8] = b"cpoe-mmr-leaf-v1";
const NODE_DST: &[u8] = b"cpoe-mmr-node-v1";
const BAG_DST: &[u8] = b"cpoe-mmr-bag-v1";

#[derive(Debug, Clone)]
pub struct Node {
    pub index: u64,
    pub height: u8,
    pub hash: [u8; HASH_SIZE],
}

/// Hash a leaf node. Binds the MMR position into the digest so identical data
/// at different positions produces distinct hashes (prevents node transplant).
pub fn hash_leaf(index: u64, data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DST);
    hasher.update([LEAF_PREFIX]);
    hasher.update(index.to_be_bytes());
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&digest);
    out
}

/// Hash an internal node. Binds the tree height so a node proven at one level
/// cannot be replayed at another (prevents height-confusion attacks).
pub fn hash_internal(height: u8, left: [u8; HASH_SIZE], right: [u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DST);
    hasher.update([INTERNAL_PREFIX]);
    hasher.update([height]);
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&digest);
    out
}

/// Hash for peak-bagging (combining peaks into the MMR root). Separate from
/// `hash_internal` because peak combination is not a tree level operation.
pub fn hash_bag(left: [u8; HASH_SIZE], right: [u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(BAG_DST);
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&digest);
    out
}

impl Node {
    pub fn new_leaf(index: u64, data: &[u8]) -> Self {
        Self {
            index,
            height: 0,
            hash: hash_leaf(index, data),
        }
    }

    pub fn new_internal(index: u64, height: u8, left: &Node, right: &Node) -> Self {
        Self {
            index,
            height,
            hash: hash_internal(height, left.hash, right.hash),
        }
    }

    pub fn serialize(&self) -> [u8; NODE_SIZE] {
        let mut buf = [0u8; NODE_SIZE];
        buf[0..8].copy_from_slice(&self.index.to_be_bytes());
        buf[8] = self.height;
        buf[9..].copy_from_slice(&self.hash);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, MmrError> {
        if data.len() < NODE_SIZE {
            return Err(MmrError::InvalidNodeData);
        }
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&data[9..41]);
        Ok(Self {
            index: u64::from_be_bytes(
                data[0..8]
                    .try_into()
                    .map_err(|_| MmrError::InvalidNodeData)?,
            ),
            height: data[8],
            hash,
        })
    }
}
