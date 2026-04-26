// SPDX-License-Identifier: Apache-2.0

//! Error types for PoSME operations.

use std::fmt;

/// Errors from PoSME proof generation or verification.
#[derive(Debug, Clone)]
pub enum PosmeError {
    /// Parameter validation failed.
    InvalidParams(String),
    /// Proof verification failed at a specific check.
    VerificationFailed(String),
    /// Merkle path verification failed.
    MerkleVerifyFailed { step_id: u32, address: u32 },
    /// Pointer-chase address mismatch during verification.
    AddressMismatch { step_id: u32, read_index: u32, expected: u32, got: u32 },
    /// Symbiotic write verification failed.
    WriteMismatch { step_id: u32 },
    /// Root chain verification failed.
    RootChainFailed { step_id: u32 },
    /// Transcript chain verification failed.
    TranscriptMismatch { step_id: u32 },
    /// Fiat-Shamir challenge derivation mismatch.
    ChallengeMismatch,
    /// Jitter entropy in entangled proof is below minimum threshold.
    JitterEntropyInsufficient { variance: f64, threshold: f64 },
}

impl fmt::Display for PosmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParams(msg) => write!(f, "invalid PoSME params: {msg}"),
            Self::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            Self::MerkleVerifyFailed { step_id, address } => {
                write!(f, "Merkle verify failed at step {step_id}, address {address}")
            }
            Self::AddressMismatch { step_id, read_index, expected, got } => {
                write!(f, "address mismatch at step {step_id}, read {read_index}: expected {expected}, got {got}")
            }
            Self::WriteMismatch { step_id } => {
                write!(f, "symbiotic write mismatch at step {step_id}")
            }
            Self::RootChainFailed { step_id } => {
                write!(f, "root chain verification failed at step {step_id}")
            }
            Self::TranscriptMismatch { step_id } => {
                write!(f, "transcript mismatch at step {step_id}")
            }
            Self::ChallengeMismatch => write!(f, "Fiat-Shamir challenge mismatch"),
            Self::JitterEntropyInsufficient { variance, threshold } => {
                write!(f, "jitter entropy insufficient: variance {variance:.2} < threshold {threshold:.2}")
            }
        }
    }
}

impl std::error::Error for PosmeError {}

/// Result type for PoSME operations.
pub type Result<T> = std::result::Result<T, PosmeError>;
