// SPDX-License-Identifier: Apache-2.0

//! Proof-of-process primitive using timing jitter for human authorship verification.
//!
//! Two engines: [`PureJitter`] (HMAC-based, economic security) and
//! [`PhysJitter`] (hardware entropy, physics security). [`HybridEngine`] selects
//! the best available source with automatic fallback.
//!
//! ```rust
//! use cpoe_jitter::{HybridEngine, PureJitter, PhysJitter, Evidence};
//!
//! let engine = HybridEngine::new(PhysJitter::default(), PureJitter::default());
//! let secret = [0u8; 32];
//! let (jitter, evidence) = engine.sample(&secret, b"keystroke data").unwrap();
//! println!("Jitter: {}us, Physics: {}", jitter, evidence.is_phys());
//! ```
//!
//! Supports `no_std` via [`PureJitter`] with explicit timestamps. The `std` feature
//! enables [`HybridEngine`], [`PhysJitter`], and [`Session`].

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "hardware"), forbid(unsafe_code))]

#[cfg(not(feature = "std"))]
extern crate alloc;

use zeroize::Zeroizing;

pub mod cognitive;
pub mod evidence;
pub mod model;
#[cfg(feature = "std")]
pub mod phys;
pub mod pure;
pub mod traits;

pub use cognitive::CognitiveTemporalMetrics;
pub use evidence::{Evidence, EvidenceChain, MAX_EVIDENCE_RECORDS};

/// Logistic sigmoid: maps a real value to [0, 1] with steepness `k` around `midpoint`.
/// Used throughout the forensic classifiers for score normalization.
#[inline]
pub fn sigmoid(x: f64, k: f64, midpoint: f64) -> f64 {
    1.0 / (1.0 + libm::exp(-k * (x - midpoint)))
}
pub use model::{Anomaly, AnomalyKind, HumanModel, SequenceStats, ValidationResult};
#[cfg(feature = "std")]
pub use phys::PhysJitter;
pub use pure::PureJitter;
#[cfg(feature = "std")]
pub use traits::EntropySource;
pub use traits::JitterEngine;

/// Derive a session-specific secret from a master key using HKDF-SHA256.
///
/// `master_key` MUST be at least 16 bytes of high-entropy material.
/// Returns [`Error::InvalidParameter`] if `master_key` is shorter than 16
/// bytes, preventing silent use of cryptographically degenerate keys.
///
/// `salt` provides domain separation between sessions. Callers SHOULD provide
/// a unique salt per session (e.g., a random nonce or session ID) to prevent
/// key reuse when `master_key` and `context` are identical across sessions.
/// If `None`, HKDF uses a zero-filled salt per RFC 5869 Section 2.2; this is
/// safe if `context` is guaranteed unique per session.
pub fn derive_session_secret(
    master_key: &[u8],
    context: &[u8],
    salt: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    if master_key.len() < 16 {
        return Err(Error::InvalidParameter(
            "master_key must be at least 16 bytes",
        ));
    }
    let hk = Hkdf::<Sha256>::new(salt, master_key);
    let mut output = [0u8; 32];
    hk.expand(context, &mut output)
        .expect("32 bytes is a valid output length for HKDF-SHA256");
    Ok(Zeroizing::new(output))
}

/// Hardware entropy sample: a SHA-256 hash of raw timing data with an
/// estimated min-entropy in bits. Produced by [`PhysJitter::sample`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PhysHash {
    pub hash: [u8; 32],
    pub entropy_bits: u8,
}

impl From<[u8; 32]> for PhysHash {
    fn from(hash: [u8; 32]) -> Self {
        Self {
            hash,
            entropy_bits: 0,
        }
    }
}

/// Jitter value in microseconds, derived from HMAC over timing entropy.
pub type Jitter = u32;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(
        feature = "std",
        error("Insufficient entropy: required {required} bits, found {found}")
    )]
    InsufficientEntropy { required: u8, found: u8 },

    #[cfg_attr(feature = "std", error("Hardware entropy not available: {reason}"))]
    HardwareUnavailable {
        #[cfg(feature = "std")]
        reason: String,
        #[cfg(not(feature = "std"))]
        reason: &'static str,
    },

    #[cfg_attr(feature = "std", error("Invalid input: {0}"))]
    InvalidInput(
        #[cfg(feature = "std")] String,
        #[cfg(not(feature = "std"))] &'static str,
    ),

    #[cfg_attr(feature = "std", error("Evidence chain overflow: exceeds {0} records"))]
    EvidenceOverflow(
        #[cfg(feature = "std")] usize,
        #[cfg(not(feature = "std"))] usize,
    ),

    #[cfg_attr(feature = "std", error("Invalid parameter: {0}"))]
    InvalidParameter(
        #[cfg(feature = "std")] &'static str,
        #[cfg(not(feature = "std"))] &'static str,
    ),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InsufficientEntropy { required, found } => {
                write!(
                    f,
                    "Insufficient entropy: required {} bits, found {}",
                    required, found
                )
            }
            Error::HardwareUnavailable { reason } => {
                write!(f, "Hardware entropy not available: {}", reason)
            }
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Error::EvidenceOverflow(max) => {
                write!(f, "Evidence chain overflow: exceeds {} records", max)
            }
            Error::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct HybridEngine {
    phys: PhysJitter,
    fallback: PureJitter,
    min_phys_entropy: u8,
    /// Number of times `sample()` fell back from hardware to pure jitter.
    hardware_fallback_count: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "std")]
impl Clone for HybridEngine {
    fn clone(&self) -> Self {
        Self {
            phys: self.phys.clone(),
            fallback: self.fallback.clone(),
            min_phys_entropy: self.min_phys_entropy,
            hardware_fallback_count: std::sync::atomic::AtomicU64::new(
                self.hardware_fallback_count
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }
}

#[cfg(feature = "std")]
impl Default for HybridEngine {
    fn default() -> Self {
        Self::new(PhysJitter::default(), PureJitter::default())
    }
}

/// Minimum entropy bits required for hardware sampling by default.
/// 8 bits = 256:1 entropy ratio, matching NIST SP 800-90B minimum
/// for conditioned noise sources on µs-resolution timers.
#[cfg(feature = "std")]
const MIN_PHYS_ENTROPY_DEFAULT: u8 = 8;

#[cfg(feature = "std")]
impl HybridEngine {
    pub fn new(phys: PhysJitter, fallback: PureJitter) -> Self {
        Self {
            phys,
            fallback,
            min_phys_entropy: MIN_PHYS_ENTROPY_DEFAULT,
            hardware_fallback_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Set the minimum entropy bits required for hardware sampling.
    ///
    /// Values above hardware capability cause `sample()` to always use pure fallback.
    pub fn with_min_entropy(mut self, bits: u8) -> Self {
        self.min_phys_entropy = bits;
        self
    }

    /// Sample jitter, preferring hardware entropy with pure HMAC fallback.
    ///
    /// Returns `(jitter_us, evidence)`. Falls back to pure jitter when hardware
    /// entropy is unavailable or below [`with_min_entropy`](Self::with_min_entropy).
    pub fn sample(&self, secret: &[u8; 32], inputs: &[u8]) -> Result<(Jitter, Evidence), Error> {
        match self.phys.sample(inputs) {
            Ok(entropy)
                if entropy.entropy_bits >= self.min_phys_entropy && self.phys.validate(entropy) =>
            {
                let jitter = self.phys.compute_jitter(secret, inputs, entropy);
                Ok((jitter, Evidence::phys(entropy, jitter)))
            }
            _ => {
                self.hardware_fallback_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let jitter = self
                    .fallback
                    .compute_jitter(secret, inputs, [0u8; 32].into());
                Ok((jitter, Evidence::pure(jitter)))
            }
        }
    }

    /// Probe whether the hardware entropy source is available.
    ///
    /// Performs one sample attempt and returns `true` on success.
    pub fn phys_available(&self) -> bool {
        self.phys.sample(b"probe").is_ok()
    }

    /// Number of times `sample()` fell back from hardware to pure jitter.
    pub fn hardware_fallback_count(&self) -> u64 {
        self.hardware_fallback_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct Session {
    secret: Zeroizing<[u8; 32]>,
    engine: HybridEngine,
    evidence: EvidenceChain,
    model: HumanModel,
}

#[cfg(feature = "std")]
impl Session {
    pub fn new(secret: &[u8; 32]) -> Self {
        let owned = Zeroizing::new(*secret);
        Self {
            evidence: EvidenceChain::with_secret(&owned),
            secret: owned,
            engine: HybridEngine::default(),
            model: HumanModel::default(),
        }
    }

    pub fn with_engine(secret: &[u8; 32], engine: HybridEngine) -> Self {
        let owned = Zeroizing::new(*secret);
        Self {
            evidence: EvidenceChain::with_secret(&owned),
            secret: owned,
            engine,
            model: HumanModel::default(),
        }
    }

    #[cfg(feature = "rand")]
    pub fn random() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::new(&secret)
    }

    pub fn sample(&mut self, inputs: &[u8]) -> Result<Jitter, Error> {
        let (jitter, evidence) = self.engine.sample(&self.secret, inputs)?;
        self.evidence.append(evidence)?;
        Ok(jitter)
    }

    pub fn evidence(&self) -> &EvidenceChain {
        &self.evidence
    }

    pub fn validate(&self) -> ValidationResult {
        self.model.validate_records(self.evidence.records())
    }

    pub fn phys_ratio(&self) -> f64 {
        self.evidence.phys_ratio()
    }

    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.evidence)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_engine_default() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];
        let inputs = b"test input";

        let result = engine.sample(&secret, inputs);
        assert!(result.is_ok());

        let (jitter, evidence) = result.unwrap();
        assert!(jitter >= 500);
        assert!(jitter < 3000);
        assert!(evidence.jitter() == jitter);
    }

    #[test]
    fn test_session_workflow() {
        let secret = [1u8; 32];
        let mut session = Session::new(&secret);

        for i in 0..30 {
            let input = format!("keystroke {}", i);
            let jitter = session.sample(input.as_bytes()).unwrap();
            assert!(jitter >= 500);
        }

        assert_eq!(session.evidence().records().len(), 30);
        let validation = session.validate();
        println!("Validation: {:?}", validation);
    }

    #[test]
    fn test_evidence_serialization() {
        let secret = [2u8; 32];
        let mut session = Session::new(&secret);

        for i in 0..10 {
            session.sample(format!("key{}", i).as_bytes()).unwrap();
        }

        let json = session.export_json().unwrap();
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"records\""));
    }

    #[test]
    fn test_pure_jitter_determinism() {
        let engine = PureJitter::default();
        let secret = [99u8; 32];
        let inputs = b"deterministic test";
        let entropy: PhysHash = [0u8; 32].into();

        let j1 = engine.compute_jitter(&secret, inputs, entropy);
        let j2 = engine.compute_jitter(&secret, inputs, entropy);

        assert_eq!(j1, j2, "Pure jitter should be deterministic");
    }

    #[test]
    fn test_empty_inputs() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];

        let result = engine.sample(&secret, b"");
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_inputs() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];
        let large_input = vec![0u8; 10000];
        let result = engine.sample(&secret, &large_input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_min_phys_entropy_enforced() {
        let engine = HybridEngine::default().with_min_entropy(255);
        let secret = [42u8; 32];

        let (_, evidence) = engine.sample(&secret, b"test").unwrap();
        assert!(
            !evidence.is_phys(),
            "Should have fallen back to pure jitter"
        );
    }
}

#[cfg(test)]
mod no_std_compatible_tests {
    use super::*;

    #[test]
    fn test_phys_hash_from_array() {
        let hash: PhysHash = [42u8; 32].into();
        assert_eq!(hash.entropy_bits, 0);
        assert_eq!(hash.hash, [42u8; 32]);
    }

    #[test]
    fn test_derive_session_secret() {
        let master = [1u8; 32];
        let secret1 = derive_session_secret(&master, b"context1", None).unwrap();
        let secret2 = derive_session_secret(&master, b"context2", None).unwrap();
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_derive_session_secret_rejects_short_key() {
        let short_key = [0xAA; 15];
        let result = derive_session_secret(&short_key, b"ctx", None);
        assert!(result.is_err());

        let min_key = [0xBB; 16];
        let result = derive_session_secret(&min_key, b"ctx", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_evidence_with_timestamp() {
        let evidence = Evidence::pure_with_timestamp(1500, 12345);
        assert_eq!(evidence.jitter(), 1500);
        assert_eq!(evidence.timestamp_us(), 12345);
        assert!(!evidence.is_phys());

        let phys_hash: PhysHash = [1u8; 32].into();
        let phys_evidence = Evidence::phys_with_timestamp(phys_hash, 2000, 67890);
        assert_eq!(phys_evidence.jitter(), 2000);
        assert_eq!(phys_evidence.timestamp_us(), 67890);
        assert!(phys_evidence.is_phys());
    }
}
