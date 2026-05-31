// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Per-session content MMR for paragraph-level Merkle trees.
//!
//! While `checkpoint_mmr.rs` tracks checkpoint hashes for anti-deletion, this
//! module tracks content segments (paragraphs/sentences/blocks) for derivation
//! proofs. When a writer uses an opaque-container app (Tinderbox, Scrivener,
//! DEVONthink), we cannot hash the container file directly. Instead, we hash
//! individual text segments into an MMR so we can later prove that content in
//! a derived document (HTML, Word) was witnessed during authoring.

use std::path::{Path, PathBuf};

use crate::content::segmentation::{segment_and_hash, ContentSegment};
use crate::error::{Error, Result};
use crate::mmr::{hash_leaf, FileStore, InclusionProof, MemoryStore, Mmr};
use crate::sentinel::app_registry::ContentGranularity;

/// Per-session content Merkle tree for content-level witnessing.
pub struct ContentMmr {
    mmr: Mmr,
    granularity: ContentGranularity,
    session_id: String,
}

impl std::fmt::Debug for ContentMmr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentMmr")
            .field("granularity", &self.granularity)
            .field("session_id", &self.session_id)
            .field("leaf_count", &self.mmr.leaf_count())
            .finish()
    }
}

impl ContentMmr {
    /// Open or create a file-backed content MMR for a session.
    pub fn open(
        mmr_dir: &Path,
        session_id: &str,
        granularity: ContentGranularity,
    ) -> Result<Self> {
        if session_id.is_empty()
            || session_id.contains('/')
            || session_id.contains('\\')
            || session_id.contains('\0')
        {
            return Err(Error::config(format!(
                "invalid content MMR session id: {session_id:?}"
            )));
        }
        std::fs::create_dir_all(mmr_dir)?;
        let store_path = mmr_dir.join(format!("content-{session_id}.mmr"));
        let store = FileStore::open(&store_path).map_err(Error::from)?;
        let mmr = Mmr::new(Box::new(store)).map_err(Error::from)?;
        Ok(Self {
            mmr,
            granularity,
            session_id: session_id.to_string(),
        })
    }

    /// Create an in-memory content MMR (for tests or ephemeral sessions).
    pub fn in_memory(session_id: &str, granularity: ContentGranularity) -> Result<Self> {
        let store = MemoryStore::new();
        let mmr = Mmr::new(Box::new(store)).map_err(Error::from)?;
        Ok(Self {
            mmr,
            granularity,
            session_id: session_id.to_string(),
        })
    }

    /// Segment text and append all segments to the MMR. Returns the segments
    /// with their inclusion proofs.
    pub fn witness_text(&self, text: &str) -> Result<Vec<WitnessedSegment>> {
        let segments = segment_and_hash(text, self.granularity);
        let mut witnessed = Vec::with_capacity(segments.len());

        for seg in segments {
            let leaf_index = self.mmr.append(&seg.hash).map_err(Error::from)?;
            self.mmr.sync().map_err(Error::from)?;
            let proof = self.mmr.generate_proof(leaf_index).map_err(Error::from)?;
            witnessed.push(WitnessedSegment {
                segment: seg,
                leaf_index,
                proof,
            });
        }
        Ok(witnessed)
    }

    /// Generate a derivation proof: given the text of a derived document,
    /// segment it and find which segments exist in this MMR.
    pub fn generate_derivation_proof(
        &self,
        derived_text: &str,
    ) -> Result<DerivationProof> {
        let derived_segments = segment_and_hash(derived_text, self.granularity);
        let derived_total = derived_segments.len();

        // For each derived segment, find matching MMR leaves by comparing
        // node hashes directly (O(1) per comparison) and only generate full
        // inclusion proofs for confirmed matches.
        let leaf_count = self.mmr.leaf_count();
        let mut matched = Vec::new();

        for d_seg in &derived_segments {
            for leaf_ord in 0..leaf_count {
                let leaf_index = self
                    .mmr
                    .get_leaf_index(leaf_ord)
                    .map_err(Error::from)?;
                let expected_hash = hash_leaf(leaf_index, &d_seg.hash);
                let node = self.mmr.get(leaf_index).map_err(Error::from)?;
                if node.hash == expected_hash {
                    let proof = self.mmr.generate_proof(leaf_index).map_err(Error::from)?;
                    matched.push(DerivationMatch {
                        derived_segment_index: d_seg.index,
                        mmr_leaf_ordinal: leaf_ord,
                        hash: d_seg.hash,
                        proof,
                    });
                    break;
                }
            }
        }

        let matched_count = matched.len();
        let coverage = if derived_total == 0 {
            0.0
        } else {
            matched_count as f64 / derived_total as f64
        };

        Ok(DerivationProof {
            session_id: self.session_id.clone(),
            granularity: self.granularity,
            mmr_root: self.root()?,
            mmr_leaf_count: leaf_count,
            matches: matched,
            derived_total,
            coverage,
        })
    }

    pub fn root(&self) -> Result<[u8; 32]> {
        self.mmr.get_root().map_err(Error::from)
    }

    pub fn leaf_count(&self) -> u64 {
        self.mmr.leaf_count()
    }

    pub fn sync(&self) -> Result<()> {
        self.mmr.sync().map_err(Error::from)
    }

    pub fn default_mmr_dir() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::config("could not determine home directory"))?;
        Ok(home.join(".writersproof").join("content-mmr"))
    }
}

#[derive(Debug)]
pub struct WitnessedSegment {
    pub segment: ContentSegment,
    pub leaf_index: u64,
    pub proof: InclusionProof,
}

#[derive(Debug)]
pub struct DerivationMatch {
    pub derived_segment_index: usize,
    pub mmr_leaf_ordinal: u64,
    pub hash: [u8; 32],
    pub proof: InclusionProof,
}

#[derive(Debug)]
pub struct DerivationProof {
    pub session_id: String,
    pub granularity: ContentGranularity,
    pub mmr_root: [u8; 32],
    pub mmr_leaf_count: u64,
    pub matches: Vec<DerivationMatch>,
    pub derived_total: usize,
    pub coverage: f64,
}

impl DerivationProof {
    pub fn verify(&self) -> bool {
        self.matches
            .iter()
            .all(|m| m.proof.verify(&m.hash).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_text_paragraph() {
        let mmr = ContentMmr::in_memory("test-session", ContentGranularity::Paragraph)
            .expect("create mmr");
        let text = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.";
        let witnessed = mmr.witness_text(text).expect("witness");
        assert_eq!(witnessed.len(), 3);
        assert_eq!(mmr.leaf_count(), 3);

        // Each proof should verify
        for w in &witnessed {
            assert!(w.proof.verify(&w.segment.hash).is_ok());
        }
    }

    #[test]
    fn test_witness_text_sentence() {
        let mmr = ContentMmr::in_memory("test-session", ContentGranularity::Sentence)
            .expect("create mmr");
        let text = "Hello world. This is a test.";
        let witnessed = mmr.witness_text(text).expect("witness");
        assert_eq!(witnessed.len(), 2);
    }

    #[test]
    fn test_derivation_proof_full_match() {
        let mmr = ContentMmr::in_memory("test-session", ContentGranularity::Paragraph)
            .expect("create mmr");
        let source = "Alpha paragraph.\n\nBeta paragraph.\n\nGamma paragraph.";
        mmr.witness_text(source).expect("witness");

        // Derived doc contains all three paragraphs
        let derived = "Alpha paragraph.\n\nBeta paragraph.\n\nGamma paragraph.";
        let proof = mmr.generate_derivation_proof(derived).expect("proof");
        assert_eq!(proof.matches.len(), 3);
        assert!((proof.coverage - 1.0).abs() < f64::EPSILON);
        assert!(proof.verify());
    }

    #[test]
    fn test_derivation_proof_partial_match() {
        let mmr = ContentMmr::in_memory("test-session", ContentGranularity::Paragraph)
            .expect("create mmr");
        let source = "Alpha.\n\nBeta.\n\nGamma.";
        mmr.witness_text(source).expect("witness");

        // Derived doc has 2 of 3 original paragraphs + 1 new one
        let derived = "Beta.\n\nGamma.\n\nDelta.";
        let proof = mmr.generate_derivation_proof(derived).expect("proof");
        assert_eq!(proof.matches.len(), 2);
        assert_eq!(proof.derived_total, 3);
        assert!((proof.coverage - 2.0 / 3.0).abs() < 0.01);
        assert!(proof.verify());
    }

    #[test]
    fn test_derivation_proof_no_match() {
        let mmr = ContentMmr::in_memory("test-session", ContentGranularity::Paragraph)
            .expect("create mmr");
        let source = "Original content here.";
        mmr.witness_text(source).expect("witness");

        let derived = "Completely different text.";
        let proof = mmr.generate_derivation_proof(derived).expect("proof");
        assert_eq!(proof.matches.len(), 0);
        assert!((proof.coverage).abs() < f64::EPSILON);
    }

    #[test]
    fn test_mmr_root_changes() {
        let mmr = ContentMmr::in_memory("test-session", ContentGranularity::Paragraph)
            .expect("create mmr");
        mmr.witness_text("First.").expect("witness 1");
        let root1 = mmr.root().expect("root");
        mmr.witness_text("Second.").expect("witness 2");
        let root2 = mmr.root().expect("root");
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_file_backed_persistence() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mmr_dir = dir.path().join("content-mmr");

        {
            let mmr =
                ContentMmr::open(&mmr_dir, "persist-test", ContentGranularity::Paragraph)
                    .expect("create");
            mmr.witness_text("Persistent content.").expect("witness");
            assert_eq!(mmr.leaf_count(), 1);
        }

        {
            let mmr =
                ContentMmr::open(&mmr_dir, "persist-test", ContentGranularity::Paragraph)
                    .expect("reopen");
            assert_eq!(mmr.leaf_count(), 1);
        }
    }

    #[test]
    fn test_incremental_witnessing() {
        let mmr = ContentMmr::in_memory("test-session", ContentGranularity::Paragraph)
            .expect("create mmr");

        // Simulate typing: witness text incrementally
        mmr.witness_text("First paragraph.").expect("w1");
        assert_eq!(mmr.leaf_count(), 1);

        mmr.witness_text("Second paragraph.").expect("w2");
        assert_eq!(mmr.leaf_count(), 2);

        // Derivation proof should find both
        let derived = "First paragraph.\n\nSecond paragraph.";
        let proof = mmr.generate_derivation_proof(derived).expect("proof");
        assert_eq!(proof.matches.len(), 2);
        assert!(proof.verify());
    }
}
