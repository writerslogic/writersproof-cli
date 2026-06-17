// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Hardware co-sign scheduling with SE-derived threshold salt.
//!
//! The Secure Enclave generates a random salt at session start that determines
//! when hardware co-signatures fire. The threshold is a function of the SE salt
//! AND the user's accumulated behavioral entropy, making the signing schedule
//! unpredictable from either component alone.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::tpm;

/// Domain separator for SE salt generation.
const SE_SALT_DST: &[u8] = b"cpoe-se-salt-v1";

/// Domain separator for entropy modulation HMAC.
const ENTROPY_MOD_DST: &[u8] = b"cpoe-entropy-mod-v1";

/// Default minimum checkpoints between hardware co-signatures.
const DEFAULT_BASE_INTERVAL: u32 = 3;

/// Default maximum additional random checkpoints derived from SE salt.
const DEFAULT_VARIANCE_RANGE: u32 = 5;

/// Modulus for entropy modulation contribution.
const ENTROPY_MOD_RANGE: u32 = 3;

/// Scheduler that determines when hardware co-signatures fire based on
/// SE-derived salt and accumulated behavioral entropy.
///
/// The threshold for triggering a hardware co-signature is:
/// ```text
/// threshold = base_interval
///           + (SE_salt[0..4] as u32 % variance_range)
///           + HMAC-SHA256(SE_salt, accumulated_entropy)[0..4] as u32 % 3
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HwCosignScheduler {
    se_salt: [u8; 32],
    #[zeroize(skip)]
    base_interval: u32,
    #[zeroize(skip)]
    variance_range: u32,
    #[zeroize(skip)]
    checkpoints_since_cosign: u32,
    #[zeroize(skip)]
    current_threshold: u32,
    accumulated_entropy: Vec<u8>,
}

impl std::fmt::Debug for HwCosignScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HwCosignScheduler")
            .field("base_interval", &self.base_interval)
            .field("variance_range", &self.variance_range)
            .field("checkpoints_since_cosign", &self.checkpoints_since_cosign)
            .field("current_threshold", &self.current_threshold)
            .field("accumulated_entropy_len", &self.accumulated_entropy.len())
            .finish_non_exhaustive()
    }
}

impl HwCosignScheduler {
    /// Create a new scheduler, deriving the SE salt from the TPM provider.
    ///
    /// The salt is produced by signing `"cpoe-se-salt-v1" || session_id` with
    /// the hardware-bound key, then taking the first 32 bytes of the SHA-256
    /// hash of that signature. This is deterministic per device per session
    /// but unpredictable to userspace.
    pub fn new(
        tpm_provider: &dyn tpm::Provider,
        session_id: &str,
        base_interval: u32,
        variance_range: u32,
    ) -> Result<Self> {
        if variance_range == 0 {
            return Err(Error::validation("variance_range must be > 0"));
        }

        let mut salt_input = Vec::with_capacity(SE_SALT_DST.len() + session_id.len());
        salt_input.extend_from_slice(SE_SALT_DST);
        salt_input.extend_from_slice(session_id.as_bytes());

        let mut sig = tpm_provider
            .sign(&salt_input)
            .map_err(|e| Error::crypto(format!("SE salt generation failed: {e}")))?;

        let salt_hash = Sha256::digest(&sig);
        sig.zeroize();
        let mut se_salt = [0u8; 32];
        se_salt.copy_from_slice(&salt_hash);

        let mut scheduler = Self {
            se_salt,
            base_interval,
            variance_range,
            checkpoints_since_cosign: 0,
            current_threshold: 0, // computed below
            accumulated_entropy: Vec::new(),
        };
        scheduler.current_threshold = scheduler.compute_threshold();
        Ok(scheduler)
    }

    /// Create a scheduler with default interval parameters.
    pub fn with_defaults(tpm_provider: &dyn tpm::Provider, session_id: &str) -> Result<Self> {
        Self::new(
            tpm_provider,
            session_id,
            DEFAULT_BASE_INTERVAL,
            DEFAULT_VARIANCE_RANGE,
        )
    }

    /// Add behavioral entropy (e.g. jitter samples) to the accumulator.
    ///
    /// This shifts the entropy modulation component of the threshold, making
    /// the next co-sign point depend on the author's actual typing behavior.
    pub fn record_entropy(&mut self, jitter_entropy: &[u8]) {
        const MAX_ENTROPY_BYTES: usize = 1024 * 1024;
        if self.accumulated_entropy.len() + jitter_entropy.len() > MAX_ENTROPY_BYTES {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(&self.accumulated_entropy);
            self.accumulated_entropy.clear();
            self.accumulated_entropy.extend_from_slice(&digest);
        }
        self.accumulated_entropy.extend_from_slice(jitter_entropy);
    }

    /// Record a checkpoint and return `true` if the threshold has been
    /// crossed, meaning it is time for a hardware co-signature.
    pub fn record_checkpoint(&mut self) -> bool {
        self.checkpoints_since_cosign = self.checkpoints_since_cosign.saturating_add(1);
        self.checkpoints_since_cosign >= self.current_threshold
    }

    /// Reset the counter after a co-signature has been performed and
    /// recompute the threshold incorporating the current entropy state.
    pub fn reset_after_cosign(&mut self) {
        self.checkpoints_since_cosign = 0;
        self.current_threshold = self.compute_threshold();
    }

    /// SHA-256 commitment to the SE salt, suitable for inclusion in evidence
    /// packets. Verifiers can confirm the same salt was used throughout a
    /// session without learning the salt itself.
    pub fn salt_commitment(&self) -> [u8; 32] {
        let hash = Sha256::digest(self.se_salt);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    /// Return the SHA-256 digest of accumulated entropy since the last co-sign,
    /// plus the raw byte count. This proves the entropy that determined the
    /// threshold crossing was genuine and allows auditors to verify the
    /// threshold computation was deterministic from the recorded data.
    pub fn entropy_digest(&self) -> ([u8; 32], usize) {
        let hash = Sha256::digest(&self.accumulated_entropy);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        (out, self.accumulated_entropy.len())
    }

    /// Drain accumulated entropy after co-sign, returning the digest and count
    /// for persistence. The raw entropy is cleared to bound memory usage.
    pub fn flush_entropy(&mut self) -> ([u8; 32], usize) {
        let result = self.entropy_digest();
        self.accumulated_entropy.clear();
        result
    }

    /// Number of checkpoints recorded since the last co-signature.
    pub fn checkpoints_since_cosign(&self) -> u32 {
        self.checkpoints_since_cosign
    }

    /// The current threshold (number of checkpoints required before next co-sign).
    pub fn current_threshold(&self) -> u32 {
        self.current_threshold
    }

    /// Compute the co-sign threshold from salt and entropy.
    ///
    /// ```text
    /// base_interval
    ///   + (SE_salt[0..4] as u32 % variance_range)
    ///   + entropy_modulation()
    /// ```
    fn compute_threshold(&self) -> u32 {
        let salt_u32 = u32::from_le_bytes([
            self.se_salt[0],
            self.se_salt[1],
            self.se_salt[2],
            self.se_salt[3],
        ]);
        let salt_component = salt_u32 % self.variance_range;
        self.base_interval + salt_component + self.entropy_modulation()
    }

    /// Entropy modulation: HMAC-SHA256(SE_salt, accumulated_entropy)[0..4] % 3.
    ///
    /// When no entropy has been accumulated yet, returns 0.
    fn entropy_modulation(&self) -> u32 {
        if self.accumulated_entropy.is_empty() {
            return 0;
        }

        let mut mac = <Hmac<Sha256>>::new_from_slice(&self.se_salt)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(ENTROPY_MOD_DST);
        mac.update(&self.accumulated_entropy);
        let result = mac.finalize().into_bytes();

        let mod_u32 = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        mod_u32 % ENTROPY_MOD_RANGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::SoftwareProvider;

    #[test]
    fn test_new_scheduler() {
        let provider = SoftwareProvider::new();
        let sched = HwCosignScheduler::new(&provider, "sess-1", 3, 5).unwrap();
        assert_eq!(sched.checkpoints_since_cosign(), 0);
        // threshold >= base_interval (3) always
        assert!(sched.current_threshold() >= 3);
        // threshold < base_interval + variance_range + ENTROPY_MOD_RANGE
        assert!(sched.current_threshold() < 3 + 5 + ENTROPY_MOD_RANGE);
    }

    #[test]
    fn test_with_defaults() {
        let provider = SoftwareProvider::new();
        let sched = HwCosignScheduler::with_defaults(&provider, "sess-2").unwrap();
        assert!(sched.current_threshold() >= DEFAULT_BASE_INTERVAL);
        assert!(
            sched.current_threshold()
                < DEFAULT_BASE_INTERVAL + DEFAULT_VARIANCE_RANGE + ENTROPY_MOD_RANGE
        );
    }

    #[test]
    fn test_zero_variance_rejected() {
        let provider = SoftwareProvider::new();
        let result = HwCosignScheduler::new(&provider, "sess-x", 3, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_record_checkpoint_triggers() {
        let provider = SoftwareProvider::new();
        let mut sched = HwCosignScheduler::new(&provider, "sess-3", 3, 5).unwrap();
        let threshold = sched.current_threshold();

        // Should not trigger before threshold
        for _ in 0..threshold.saturating_sub(1) {
            assert!(!sched.record_checkpoint());
        }
        // Should trigger at threshold
        assert!(sched.record_checkpoint());
        assert_eq!(sched.checkpoints_since_cosign(), threshold);
    }

    #[test]
    fn test_reset_after_cosign() {
        let provider = SoftwareProvider::new();
        let mut sched = HwCosignScheduler::new(&provider, "sess-4", 3, 5).unwrap();

        // Advance to trigger
        while !sched.record_checkpoint() {}
        sched.reset_after_cosign();
        assert_eq!(sched.checkpoints_since_cosign(), 0);
        // Threshold recomputed (same salt, no entropy change, so same value)
        assert!(sched.current_threshold() >= 3);
    }

    #[test]
    fn test_entropy_shifts_threshold() {
        let provider = SoftwareProvider::new();
        let mut sched = HwCosignScheduler::new(&provider, "sess-5", 3, 5).unwrap();
        let t0 = sched.current_threshold();

        // Add entropy and reset to recompute
        sched.record_entropy(b"some jitter data from typing");
        sched.reset_after_cosign();
        let t1 = sched.current_threshold();

        // Different entropy may produce a different threshold
        // (not guaranteed per single sample, but the mechanism is exercised)
        // Both must be in valid range
        assert!((3..3 + 5 + ENTROPY_MOD_RANGE).contains(&t0));
        assert!((3..3 + 5 + ENTROPY_MOD_RANGE).contains(&t1));
    }

    #[test]
    fn test_salt_commitment_stable() {
        let provider = SoftwareProvider::new();
        let sched = HwCosignScheduler::new(&provider, "sess-6", 3, 5).unwrap();
        let c1 = sched.salt_commitment();
        let c2 = sched.salt_commitment();
        assert_eq!(c1, c2);
        // Commitment is non-zero
        assert_ne!(c1, [0u8; 32]);
    }

    #[test]
    fn test_different_sessions_different_salts() {
        let provider = SoftwareProvider::new();
        let s1 = HwCosignScheduler::new(&provider, "session-a", 3, 5).unwrap();
        let s2 = HwCosignScheduler::new(&provider, "session-b", 3, 5).unwrap();
        // Different session IDs produce different salt commitments
        assert_ne!(s1.salt_commitment(), s2.salt_commitment());
    }

    #[test]
    fn test_different_providers_different_salts() {
        let p1 = SoftwareProvider::new();
        let p2 = SoftwareProvider::new();
        let s1 = HwCosignScheduler::new(&p1, "same-sess", 3, 5).unwrap();
        let s2 = HwCosignScheduler::new(&p2, "same-sess", 3, 5).unwrap();
        // Different devices produce different salt commitments
        assert_ne!(s1.salt_commitment(), s2.salt_commitment());
    }

    #[test]
    fn test_full_cosign_cycle() {
        let provider = SoftwareProvider::new();
        let mut sched = HwCosignScheduler::new(&provider, "sess-7", 2, 3).unwrap();

        let mut cosign_count = 0;
        let mut total_checkpoints = 0;

        // Run through several co-sign cycles
        for _ in 0..50 {
            total_checkpoints += 1;
            sched.record_entropy(&[total_checkpoints as u8]);
            if sched.record_checkpoint() {
                cosign_count += 1;
                sched.reset_after_cosign();
            }
        }

        // With base=2, variance=3, mod=3, threshold is 2..8, so across 50
        // checkpoints we should have triggered multiple co-signs
        assert!(
            cosign_count >= 2,
            "expected multiple co-signs, got {cosign_count}"
        );
    }

    #[test]
    fn test_entropy_modulation_bounded() {
        let provider = SoftwareProvider::new();
        let mut sched = HwCosignScheduler::new(&provider, "sess-8", 3, 5).unwrap();

        // Test with various entropy inputs
        for i in 0..100u8 {
            sched.record_entropy(&[i; 16]);
            let t = sched.compute_threshold();
            assert!(t >= 3, "threshold {t} below base_interval");
            assert!(t < 3 + 5 + ENTROPY_MOD_RANGE, "threshold {t} exceeds max");
        }
    }
}
