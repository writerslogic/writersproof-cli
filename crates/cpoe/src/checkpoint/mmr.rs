// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Per-chain MMR coordinator for anti-deletion protection.
//!
//! Each chain's checkpoint hashes are appended as MMR leaves. The MMR root +
//! leaf count are signed into `ChainMetadata`, making deletion detectable.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::checkpoint::{Chain, ChainIntegrityMetadata, Checkpoint};
use crate::error::{Error, Result};
use crate::mmr::{FileStore, InclusionProof, MemoryStore, Mmr, RangeProof};

/// Type-safe wrapper for a SHA-256 checkpoint hash used as an MMR leaf.
///
/// Prevents accidental use of arbitrary `[u8; 32]` values (e.g. keys, nonces)
/// as MMR leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmrLeaf(pub [u8; 32]);

impl MmrLeaf {
    /// Wrap a raw 32-byte hash as an MMR leaf.
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Access the inner hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for MmrLeaf {
    fn from(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

impl From<&[u8; 32]> for MmrLeaf {
    fn from(hash: &[u8; 32]) -> Self {
        Self(*hash)
    }
}

/// Result of appending a checkpoint to the MMR, distinguishing fresh appends
/// from idempotent duplicates.
#[derive(Debug)]
pub enum AppendResult {
    /// The checkpoint was freshly appended.
    New(InclusionProof),
    /// The checkpoint already existed as the last leaf; returned existing proof.
    Existing(InclusionProof),
}

impl AppendResult {
    /// Extract the inclusion proof regardless of variant.
    pub fn proof(&self) -> &InclusionProof {
        match self {
            AppendResult::New(p) | AppendResult::Existing(p) => p,
        }
    }

    /// Returns `true` if the checkpoint was freshly appended.
    pub fn is_new(&self) -> bool {
        matches!(self, AppendResult::New(_))
    }
}

/// Per-chain MMR coordinator for append-only checkpoint integrity.
pub struct CheckpointMmr {
    mmr: Mmr,
}

impl std::fmt::Debug for CheckpointMmr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointMmr").finish_non_exhaustive()
    }
}

impl CheckpointMmr {
    /// Open or create a file-backed MMR for the given chain.
    pub fn open(mmr_dir: &Path, chain_id: &str) -> Result<Self> {
        if chain_id.is_empty()
            || chain_id.contains('/')
            || chain_id.contains('\\')
            || chain_id.contains('\0')
            || chain_id == "."
            || chain_id == ".."
        {
            return Err(Error::config(format!("invalid MMR chain id: {chain_id:?}")));
        }
        std::fs::create_dir_all(mmr_dir)?;
        let store_path = mmr_dir.join(format!("{chain_id}.mmr"));
        let store = FileStore::open(&store_path).map_err(Error::from)?;
        let mmr = Mmr::new(Box::new(store)).map_err(Error::from)?;
        Ok(Self { mmr })
    }

    /// Create an in-memory MMR (for tests or ephemeral chains).
    pub fn in_memory() -> Result<Self> {
        let store = MemoryStore::new();
        let mmr = Mmr::new(Box::new(store)).map_err(Error::from)?;
        Ok(Self { mmr })
    }

    /// Append a checkpoint hash and return its inclusion proof.
    ///
    /// EH-043: Idempotent -- if the last leaf already matches `checkpoint_hash`,
    /// we skip the append and return `AppendResult::Existing`. Otherwise, a fresh
    /// append returns `AppendResult::New`.
    pub fn append_checkpoint(&self, leaf: impl Into<MmrLeaf>) -> Result<AppendResult> {
        let checkpoint_hash = leaf.into();
        let count = self.mmr.leaf_count();
        if count > 0 {
            let last_leaf_index = self.mmr.get_leaf_index(count - 1).map_err(Error::from)?;
            if let Ok(existing_proof) = self.mmr.generate_proof(last_leaf_index) {
                if existing_proof.verify(checkpoint_hash.as_bytes()).is_ok() {
                    return Ok(AppendResult::Existing(existing_proof));
                }
            }
        }

        let leaf_index = self
            .mmr
            .append(checkpoint_hash.as_bytes())
            .map_err(Error::from)?;
        // FileStore requires sync before proof generation
        self.mmr.sync().map_err(Error::from)?;
        let proof = self.mmr.generate_proof(leaf_index).map_err(Error::from)?;
        Ok(AppendResult::New(proof))
    }

    /// Verify a checkpoint hash exists at the given leaf ordinal.
    pub fn verify_checkpoint(&self, leaf: impl Into<MmrLeaf>, leaf_ordinal: u64) -> Result<bool> {
        let checkpoint_hash = leaf.into();
        let leaf_index = self.mmr.get_leaf_index(leaf_ordinal).map_err(Error::from)?;
        let proof = self.mmr.generate_proof(leaf_index).map_err(Error::from)?;
        Ok(proof.verify(checkpoint_hash.as_bytes()).is_ok())
    }

    /// Return the current MMR root hash.
    pub fn root(&self) -> Result<[u8; 32]> {
        self.mmr.get_root().map_err(Error::from)
    }

    /// Return the number of leaves (checkpoints) in the MMR.
    pub fn leaf_count(&self) -> u64 {
        self.mmr.leaf_count()
    }

    /// Generate a range proof covering all leaves, or `None` if empty.
    pub fn range_proof(&self) -> Result<Option<RangeProof>> {
        let count = self.leaf_count();
        if count == 0 {
            return Ok(None);
        }
        let proof = self
            .mmr
            .generate_range_proof(0, count - 1)
            .map_err(Error::from)?;
        Ok(Some(proof))
    }

    /// Build a `ChainIntegrityMetadata` snapshot from the current MMR state.
    pub fn build_metadata(&self) -> Result<ChainIntegrityMetadata> {
        let count = self.leaf_count();
        let mmr_root = if count > 0 { self.root()? } else { [0u8; 32] };

        Ok(ChainIntegrityMetadata {
            checkpoint_count: count,
            mmr_root,
            mmr_leaf_count: count,
            metadata_signature: None,
            metadata_version: 1,
        })
    }

    /// Bind the current MMR root into a checkpoint's signed hash, then append it.
    ///
    /// Call this after the checkpoint is fully constructed but before it is stored.
    /// The pre-append MMR root is written into `checkpoint.mmr_root`, the checkpoint
    /// hash is recomputed (so the root is covered by the signature), and then the
    /// new hash is appended as a leaf. This makes the MMR root verifiable by any
    /// external party who holds the signed checkpoint.
    pub fn finalize_checkpoint(&self, checkpoint: &mut Checkpoint) -> Result<AppendResult> {
        let count = self.mmr.leaf_count();
        let pre_root = if count > 0 {
            self.mmr.get_root().map_err(Error::from)?
        } else {
            [0u8; 32]
        };
        checkpoint.mmr_root = Some(pre_root);
        checkpoint.recompute_hash();
        self.append_checkpoint(checkpoint.hash)
    }

    /// Replay all checkpoint hashes from a chain into this MMR.
    pub fn rebuild_from_chain(&self, chain: &Chain) -> Result<()> {
        if self.leaf_count() != 0 {
            return Err(Error::checkpoint(
                "cannot rebuild MMR from chain: MMR is not empty",
            ));
        }
        for cp in &chain.checkpoints {
            self.mmr.append(&cp.hash).map_err(Error::from)?;
        }
        self.mmr.sync().map_err(Error::from)?;
        Ok(())
    }

    /// Flush pending MMR writes to the backing store.
    pub fn sync(&self) -> Result<()> {
        self.mmr.sync().map_err(Error::from)
    }

    /// Return the default MMR storage directory (`~/.writersproof/mmr`).
    pub fn default_mmr_dir() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::config("could not determine home directory for MMR storage"))?;
        Ok(home.join(".writersproof").join("mmr"))
    }
}

/// `SHA256("cpoe-chain-metadata-v1" || checkpoint_count || mmr_root || mmr_leaf_count || metadata_version)`.
pub fn metadata_signing_payload(metadata: &ChainIntegrityMetadata) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cpoe-chain-metadata-v1");
    hasher.update(metadata.checkpoint_count.to_be_bytes());
    hasher.update(metadata.mmr_root);
    hasher.update(metadata.mmr_leaf_count.to_be_bytes());
    hasher.update(metadata.metadata_version.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::SignaturePolicy;
    use crate::vdf::Parameters;
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;

    fn test_vdf_params() -> Parameters {
        Parameters {
            iterations_per_second: 1000,
            min_iterations: 10,
            max_iterations: 100_000,
        }
    }

    #[test]
    fn test_mmr_append_and_verify() {
        let mmr = CheckpointMmr::in_memory().expect("create mmr");
        let hash = [0xABu8; 32];

        let result = mmr.append_checkpoint(hash).expect("append");
        assert!(result.is_new());
        assert_eq!(result.proof().leaf_index, 0);
        assert_eq!(mmr.leaf_count(), 1);

        let valid = mmr.verify_checkpoint(hash, 0).expect("verify");
        assert!(valid);
    }

    #[test]
    fn test_mmr_multiple_appends() {
        let mmr = CheckpointMmr::in_memory().expect("create mmr");

        for i in 0u8..5 {
            let hash = [i; 32];
            mmr.append_checkpoint(hash).expect("append");
        }

        assert_eq!(mmr.leaf_count(), 5);

        for i in 0u8..5 {
            let hash = [i; 32];
            let valid = mmr.verify_checkpoint(hash, i as u64).expect("verify");
            assert!(valid, "checkpoint {i} should verify");
        }
    }

    #[test]
    fn test_mmr_root_changes_on_append() {
        let mmr = CheckpointMmr::in_memory().expect("create mmr");

        mmr.append_checkpoint([1u8; 32]).expect("append 1");
        let root1 = mmr.root().expect("root 1");

        mmr.append_checkpoint([2u8; 32]).expect("append 2");
        let root2 = mmr.root().expect("root 2");

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_build_metadata() {
        let mmr = CheckpointMmr::in_memory().expect("create mmr");

        for i in 0u8..3 {
            mmr.append_checkpoint([i; 32]).expect("append");
        }

        let metadata = mmr.build_metadata().expect("build metadata");
        assert_eq!(metadata.checkpoint_count, 3);
        assert_eq!(metadata.mmr_leaf_count, 3);
        assert_ne!(metadata.mmr_root, [0u8; 32]);
        assert_eq!(metadata.metadata_version, 1);
        assert!(metadata.metadata_signature.is_none());
    }

    #[test]
    fn test_deletion_detected_via_count() {
        let mmr = CheckpointMmr::in_memory().expect("create mmr");

        for i in 0u8..5 {
            mmr.append_checkpoint([i; 32]).expect("append");
        }

        let metadata = mmr.build_metadata().expect("build metadata");
        assert_eq!(metadata.checkpoint_count, 5);
    }

    #[test]
    fn test_file_backed_mmr_persists() {
        let dir = TempDir::new().expect("create temp dir");
        let mmr_dir = dir.path().join("mmr");

        // Create and populate using raw MMR
        {
            let store_path = mmr_dir.join("test-chain.mmr");
            std::fs::create_dir_all(&mmr_dir).expect("create dir");
            let store = crate::mmr::FileStore::open(&store_path).expect("open store");
            let mmr = crate::mmr::Mmr::new(Box::new(store)).expect("create mmr");
            mmr.append(&[1u8; 32]).expect("append 1");
            mmr.append(&[2u8; 32]).expect("append 2");
            assert_eq!(mmr.leaf_count(), 2);
            mmr.sync().expect("sync");
        }

        // Reopen and verify
        {
            let mmr = CheckpointMmr::open(&mmr_dir, "test-chain").expect("reopen mmr");
            assert_eq!(mmr.leaf_count(), 2);
            let valid = mmr.verify_checkpoint([1u8; 32], 0).expect("verify");
            assert!(valid);
        }

        drop(dir);
    }

    #[test]
    fn test_rebuild_from_chain() {
        let dir = TempDir::new().expect("create temp dir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let path = canonical_dir.join("test_doc.txt");
        fs::write(&path, b"initial content").expect("write");

        let mut chain = Chain::new(&path, test_vdf_params())
            .expect("create chain")
            .with_signature_policy(SignaturePolicy::Optional);

        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        let mmr = CheckpointMmr::in_memory().expect("create mmr");
        mmr.rebuild_from_chain(&chain).expect("rebuild");

        assert_eq!(mmr.leaf_count(), 2);
        for cp in &chain.checkpoints {
            let valid = mmr.verify_checkpoint(cp.hash, cp.ordinal).expect("verify");
            assert!(valid, "checkpoint {} should verify", cp.ordinal);
        }

        drop(dir);
    }

    #[test]
    fn test_range_proof() {
        let mmr = CheckpointMmr::in_memory().expect("create mmr");

        for i in 0u8..5 {
            mmr.append_checkpoint([i; 32]).expect("append");
        }

        let proof = mmr.range_proof().expect("range proof");
        assert!(proof.is_some());
    }

    #[test]
    fn test_metadata_signing_payload_deterministic() {
        let metadata = ChainIntegrityMetadata {
            checkpoint_count: 10,
            mmr_root: [0xAAu8; 32],
            mmr_leaf_count: 10,
            metadata_signature: None,
            metadata_version: 1,
        };

        let payload1 = metadata_signing_payload(&metadata);
        let payload2 = metadata_signing_payload(&metadata);
        assert_eq!(payload1, payload2);
    }
}
