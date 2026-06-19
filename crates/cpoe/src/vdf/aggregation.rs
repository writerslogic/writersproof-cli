// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! VDF proof aggregation per the CPoE RFC.
//!
//! Reduces O(n) sequential VDF recomputation to O(1) or O(log n) verification
//! of entire checkpoint chains.
//!
//! # Aggregation Methods
//!
//! - **Merkle VDF Tree**: O(log n) via Merkle inclusion proofs
//! - **SNARK**: O(1), requires trusted setup
//! - **STARK**: O(log n), no trusted setup
//!
//! # Security Model
//!
//! Trade-off between verification efficiency and trust:
//! - Full VDF recomputation: zero trust, O(n)
//! - Merkle + sampling: statistical trust, O(k log n)
//! - SNARK: trusted setup, O(1)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// VDF aggregation method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMethod {
    /// Merkle tree over VDF outputs with sampled inclusion proofs.
    MerkleVdfTree,
    /// Groth16 SNARK proof (requires trusted setup).
    SnarkGroth16,
    /// PLONK SNARK proof (universal setup).
    SnarkPlonk,
    /// STARK proof (no trusted setup, polylogarithmic verification).
    Stark,
    /// Recursive SNARK for incremental aggregation.
    RecursiveSnark,
}

/// SNARK proof scheme (curve + proof system)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnarkScheme {
    /// Groth16 over BN254 curve.
    Groth16Bn254,
    /// Groth16 over BLS12-381 curve.
    Groth16Bls12381,
    /// PLONK over BN254 curve.
    PlonkBn254,
    /// PLONK over BLS12-381 curve.
    PlonkBls12381,
}

/// Aggregation proof metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover_version: Option<String>,

    /// Proof generation wall-clock time (ms)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_generation_time_ms: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_size_bytes: Option<u32>,

    /// Used when the full key is well-known and omitted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_key_id: Option<String>,

    /// Included when the key is not well-known
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_key: Option<Vec<u8>>,
}

/// Single sampled checkpoint with its Merkle inclusion path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleSample {
    pub checkpoint_index: u32,
    /// Hashes from leaf to root
    pub merkle_path: Vec<String>,
    /// Whether the aggregator verified the VDF for this sample
    pub vdf_verified: bool,
}

/// Merkle VDF tree proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleVdfProof {
    pub root_hash: String,
    /// Sum of iterations across all checkpoints
    pub total_iterations: u64,
    pub checkpoint_count: u32,

    /// Probabilistic verification samples
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sampled_proofs: Vec<MerkleSample>,

    /// Optional trusted-aggregator signature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregator_signature: Option<String>,
}

/// SNARK VDF proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkVdfProof {
    pub scheme: SnarkScheme,
    pub proof_bytes: Vec<u8>,
    /// Verification key ID or inline key
    pub verification_key: String,
    pub public_inputs: Vec<Vec<u8>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_version: Option<String>,

    /// For auditability of the trusted setup ceremony
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_ceremony_hash: Option<Vec<u8>>,
}

/// VDF aggregate proof, polymorphic over `AggregationMethod`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfAggregateProof {
    pub checkpoints_covered: u32,
    pub method: AggregationMethod,
    /// Serialized inner proof (Merkle, SNARK, etc.)
    pub aggregate_proof: Vec<u8>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AggregateMetadata>,
}

impl VdfAggregateProof {
    /// Wrap a `MerkleVdfProof` into an aggregate proof
    pub fn from_merkle(proof: MerkleVdfProof) -> Result<Self, serde_json::Error> {
        let proof_bytes = serde_json::to_vec(&proof)?;
        Ok(Self {
            checkpoints_covered: proof.checkpoint_count,
            method: AggregationMethod::MerkleVdfTree,
            aggregate_proof: proof_bytes,
            metadata: None,
        })
    }

    /// Wrap a `SnarkVdfProof` into an aggregate proof
    pub fn from_snark(
        proof: SnarkVdfProof,
        checkpoint_count: u32,
    ) -> Result<Self, serde_json::Error> {
        let method = match proof.scheme {
            SnarkScheme::Groth16Bn254 | SnarkScheme::Groth16Bls12381 => {
                AggregationMethod::SnarkGroth16
            }
            SnarkScheme::PlonkBn254 | SnarkScheme::PlonkBls12381 => AggregationMethod::SnarkPlonk,
        };
        let proof_bytes = serde_json::to_vec(&proof)?;
        Ok(Self {
            checkpoints_covered: checkpoint_count,
            method,
            aggregate_proof: proof_bytes,
            metadata: None,
        })
    }

    /// Attach generation metadata (builder pattern)
    pub fn with_metadata(mut self, metadata: AggregateMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Deserialize inner proof as `MerkleVdfProof`; errors if method mismatches
    pub fn as_merkle(&self) -> Result<MerkleVdfProof, AggregateError> {
        if self.method != AggregationMethod::MerkleVdfTree {
            return Err(AggregateError::WrongMethod);
        }
        serde_json::from_slice(&self.aggregate_proof)
            .map_err(|_| AggregateError::DeserializationError)
    }

    /// Deserialize inner proof as `SnarkVdfProof`; errors if method mismatches
    pub fn as_snark(&self) -> Result<SnarkVdfProof, AggregateError> {
        match self.method {
            AggregationMethod::SnarkGroth16 | AggregationMethod::SnarkPlonk => {
                serde_json::from_slice(&self.aggregate_proof)
                    .map_err(|_| AggregateError::DeserializationError)
            }
            _ => Err(AggregateError::WrongMethod),
        }
    }

    /// Human-readable verification complexity (big-O)
    pub fn verification_complexity(&self) -> &'static str {
        match self.method {
            AggregationMethod::MerkleVdfTree => "O(k * log n) where k = samples",
            AggregationMethod::SnarkGroth16 => "O(1) constant time",
            AggregationMethod::SnarkPlonk => "O(1) constant time",
            AggregationMethod::Stark => "O(log n) polylogarithmic",
            AggregationMethod::RecursiveSnark => "O(1) constant time",
        }
    }

    /// Whether this scheme depends on a trusted setup ceremony
    pub fn requires_trusted_setup(&self) -> bool {
        matches!(
            self.method,
            AggregationMethod::SnarkGroth16 | AggregationMethod::RecursiveSnark
        )
    }
}

/// Aggregate proof operation errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AggregateError {
    /// Attempted to extract a proof type that does not match the method.
    #[error("Attempted to extract wrong proof type")]
    WrongMethod,
    /// Inner proof bytes failed to deserialize.
    #[error("Failed to deserialize proof")]
    DeserializationError,
    /// Aggregate proof verification failed.
    #[error("Proof verification failed")]
    VerificationFailed,
    /// Merkle inclusion path is invalid.
    #[error("Invalid Merkle path")]
    InvalidMerklePath,
    /// Required verification key not found.
    #[error("Verification key not found")]
    MissingVerificationKey,
}

#[derive(Debug)]
/// Incremental builder for `MerkleVdfProof`
pub struct MerkleVdfBuilder {
    leaf_hashes: Vec<String>,
    total_iterations: u64,
}

impl MerkleVdfBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self {
            leaf_hashes: Vec::new(),
            total_iterations: 0,
        }
    }

    /// Append a VDF leaf: `leaf_hash` = H(input || output || iterations)
    pub fn add_vdf(&mut self, leaf_hash: String, iterations: u64) {
        self.leaf_hashes.push(leaf_hash);
        self.total_iterations += iterations;
    }

    /// Finalize the tree and return the proof
    pub fn build(self) -> MerkleVdfProof {
        let root_hash = self.compute_merkle_root();
        MerkleVdfProof {
            root_hash,
            total_iterations: self.total_iterations,
            checkpoint_count: u32::try_from(self.leaf_hashes.len()).unwrap_or_else(|_| {
                log::warn!(
                    "checkpoint_count overflow: {} exceeds u32::MAX, clamped",
                    self.leaf_hashes.len()
                );
                u32::MAX
            }),
            sampled_proofs: Vec::new(),
            aggregator_signature: None,
        }
    }

    fn compute_merkle_root(&self) -> String {
        if self.leaf_hashes.is_empty() {
            return String::new();
        }

        if self.leaf_hashes.len() == 1 {
            let mut hasher = Sha256::new();
            hasher.update([0x00u8]); // leaf domain separation
            hasher.update(self.leaf_hashes[0].as_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            return hex::encode(digest);
        }

        let mut level: Vec<[u8; 32]> = self
            .leaf_hashes
            .iter()
            .map(|leaf| {
                let mut hasher = Sha256::new();
                hasher.update([0x00u8]); // leaf domain separation
                hasher.update(leaf.as_bytes());
                hasher.finalize().into()
            })
            .collect();

        while level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let hash: [u8; 32] = if chunk.len() == 2 {
                    let mut hasher = Sha256::new();
                    hasher.update([0x01u8]); // internal node domain separation
                    hasher.update(chunk[0]);
                    hasher.update(chunk[1]);
                    hasher.finalize().into()
                } else {
                    // Odd node promoted: re-hash to maintain uniform structure
                    let mut hasher = Sha256::new();
                    hasher.update([0x01u8]); // internal node domain separation
                    hasher.update(chunk[0]);
                    hasher.finalize().into()
                };
                next_level.push(hash);
            }
            level = next_level;
        }

        hex::encode(level[0])
    }
}

impl Default for MerkleVdfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification mode for aggregate proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// Recompute all VDFs -- maximum assurance, O(n)
    Full,
    /// Randomly sample and verify k proofs -- statistical assurance
    Sampled { sample_count: u32 },
    /// Trust aggregator signature only
    TrustedAggregator,
    /// Verify SNARK proof only -- O(1)
    SnarkOnly,
}

impl VerificationMode {
    /// Trust assumptions required by this mode
    pub fn trust_assumptions(&self) -> &'static str {
        match self {
            Self::Full => "None - cryptographically verified",
            Self::Sampled { .. } => "Statistical - high probability all VDFs valid",
            Self::TrustedAggregator => "Trusted aggregator - rely on third party",
            Self::SnarkOnly => "Trusted setup ceremony - cryptographic assumptions",
        }
    }

    /// Recommended use cases
    pub fn suggested_use_case(&self) -> &'static str {
        match self {
            Self::Full => "Litigation, forensics, maximum assurance",
            Self::Sampled { .. } => "Academic review, publication verification",
            Self::TrustedAggregator => "Real-time display, low-stakes checks",
            Self::SnarkOnly => "High-volume processing, enterprise verification",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_builder() {
        let mut builder = MerkleVdfBuilder::new();
        builder.add_vdf("leaf1".to_string(), 1000);
        builder.add_vdf("leaf2".to_string(), 2000);
        builder.add_vdf("leaf3".to_string(), 3000);

        let proof = builder.build();
        assert_eq!(proof.checkpoint_count, 3);
        assert_eq!(proof.total_iterations, 6000);
        assert!(!proof.root_hash.is_empty());
        assert_eq!(proof.root_hash.len(), 64);
        assert!(proof.root_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_merkle_root_is_deterministic() {
        let build = || {
            let mut b = MerkleVdfBuilder::new();
            b.add_vdf("a".to_string(), 1);
            b.add_vdf("b".to_string(), 2);
            b.build().root_hash
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn test_merkle_root_differs_for_different_leaves() {
        let mut b1 = MerkleVdfBuilder::new();
        b1.add_vdf("x".to_string(), 1);
        b1.add_vdf("y".to_string(), 2);

        let mut b2 = MerkleVdfBuilder::new();
        b2.add_vdf("y".to_string(), 1);
        b2.add_vdf("x".to_string(), 2);

        assert_ne!(b1.build().root_hash, b2.build().root_hash);
    }

    #[test]
    fn test_aggregate_from_merkle() {
        let merkle = MerkleVdfProof {
            root_hash: "root".to_string(),
            total_iterations: 1000,
            checkpoint_count: 5,
            sampled_proofs: vec![],
            aggregator_signature: None,
        };

        let aggregate = VdfAggregateProof::from_merkle(merkle).unwrap();
        assert_eq!(aggregate.method, AggregationMethod::MerkleVdfTree);
        assert_eq!(aggregate.checkpoints_covered, 5);
    }

    #[test]
    fn test_aggregate_roundtrip() {
        let merkle = MerkleVdfProof {
            root_hash: "test_root".to_string(),
            total_iterations: 5000,
            checkpoint_count: 10,
            sampled_proofs: vec![MerkleSample {
                checkpoint_index: 3,
                merkle_path: vec!["h1".to_string(), "h2".to_string()],
                vdf_verified: true,
            }],
            aggregator_signature: Some("sig".to_string()),
        };

        let aggregate = VdfAggregateProof::from_merkle(merkle.clone()).unwrap();
        let extracted = aggregate.as_merkle().unwrap();

        assert_eq!(extracted.root_hash, merkle.root_hash);
        assert_eq!(extracted.total_iterations, merkle.total_iterations);
    }

    #[test]
    fn test_wrong_method_error() {
        let merkle = MerkleVdfProof {
            root_hash: "root".to_string(),
            total_iterations: 100,
            checkpoint_count: 1,
            sampled_proofs: vec![],
            aggregator_signature: None,
        };

        let aggregate = VdfAggregateProof::from_merkle(merkle).unwrap();
        let result = aggregate.as_snark();
        assert_eq!(result.unwrap_err(), AggregateError::WrongMethod);
    }

    #[test]
    fn test_verification_mode_metadata() {
        let full = VerificationMode::Full;
        assert!(full.trust_assumptions().contains("None"));

        let sampled = VerificationMode::Sampled { sample_count: 10 };
        assert!(sampled.trust_assumptions().contains("Statistical"));
    }

    #[test]
    fn test_trusted_setup_check() {
        let snark = VdfAggregateProof {
            checkpoints_covered: 10,
            method: AggregationMethod::SnarkGroth16,
            aggregate_proof: vec![],
            metadata: None,
        };
        assert!(snark.requires_trusted_setup());

        let merkle = VdfAggregateProof {
            checkpoints_covered: 10,
            method: AggregationMethod::MerkleVdfTree,
            aggregate_proof: vec![],
            metadata: None,
        };
        assert!(!merkle.requires_trusted_setup());
    }

    #[test]
    fn test_serialization() {
        let proof = VdfAggregateProof {
            checkpoints_covered: 50,
            method: AggregationMethod::Stark,
            aggregate_proof: vec![1, 2, 3],
            metadata: Some(AggregateMetadata {
                prover_version: Some("1.0".to_string()),
                proof_generation_time_ms: Some(5000),
                proof_size_bytes: Some(1024),
                verification_key_id: None,
                verification_key: None,
            }),
        };

        let json = serde_json::to_string(&proof).unwrap();
        let parsed: VdfAggregateProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, AggregationMethod::Stark);
    }
}
