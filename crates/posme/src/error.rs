// SPDX-License-Identifier: Apache-2.0

//! Error types for PoSME operations.

/// `f64` wrapper with bitwise `Eq` (IEEE 754 bit-pattern equality).
#[derive(Debug, Clone, Copy)]
pub struct OrderedF64(pub f64);

impl PartialEq for OrderedF64 {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for OrderedF64 {}

impl std::fmt::Display for OrderedF64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum PosmeError {
    #[error("invalid PoSME params: {0}")]
    InvalidParams(Box<str>),

    #[error("verification failed: {0}")]
    VerificationFailed(Box<str>),

    #[error("Merkle verify failed at step {step_id}, address {address}")]
    MerkleVerifyFailed { step_id: u32, address: u32 },

    #[error(
        "address mismatch at step {step_id}, read {read_index}: expected {expected}, got {got}"
    )]
    AddressMismatch {
        step_id: u32,
        read_index: u32,
        expected: u32,
        got: u32,
    },

    #[error("symbiotic write mismatch at step {step_id}")]
    WriteMismatch { step_id: u32 },

    #[error("root chain verification failed at step {step_id}")]
    RootChainFailed { step_id: u32 },

    #[error("transcript mismatch at step {step_id}")]
    TranscriptMismatch { step_id: u32 },

    #[error("Fiat-Shamir challenge mismatch")]
    ChallengeMismatch,

    #[error("jitter entropy insufficient: variance {variance} < threshold {threshold}")]
    JitterEntropyInsufficient {
        variance: OrderedF64,
        threshold: OrderedF64,
    },
}

impl PosmeError {
    pub(crate) fn invalid_params(msg: impl std::fmt::Display) -> Self {
        Self::InvalidParams(msg.to_string().into_boxed_str())
    }

    pub(crate) fn verification_failed(msg: impl std::fmt::Display) -> Self {
        Self::VerificationFailed(msg.to_string().into_boxed_str())
    }

    pub(crate) fn jitter_entropy(variance: f64, threshold: f64) -> Self {
        Self::JitterEntropyInsufficient {
            variance: OrderedF64(variance),
            threshold: OrderedF64(threshold),
        }
    }
}

pub type Result<T> = std::result::Result<T, PosmeError>;
