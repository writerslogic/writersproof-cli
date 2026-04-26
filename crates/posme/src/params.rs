// SPDX-License-Identifier: Apache-2.0

//! PoSME parameter types and tier presets per draft-condrey-cfrg-posme.

use crate::error::{PosmeError, Result};

/// PoSME execution parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PosmeParams {
    /// Number of 64-byte blocks in the arena (N). Must be a power of 2.
    pub arena_blocks: u32,
    /// Total sequential steps to execute (K). Must be >= N.
    pub total_steps: u32,
    /// Pointer-chase reads per step (d). Must be >= 4.
    pub reads_per_step: u8,
    /// Fiat-Shamir challenged steps (Q). Must be >= 2.
    pub challenges: u16,
    /// Recursive provenance depth (R). Must be >= 1.
    pub recursion_depth: u8,
}

// Minimum parameter bounds per the draft.
const MIN_ARENA_BLOCKS: u32 = 1 << 10; // 64 KiB (relaxed for testing)
const MIN_READS_PER_STEP: u8 = 4;
const MIN_CHALLENGES: u16 = 2;
const MIN_RECURSION_DEPTH: u8 = 1;
const MAX_RECURSION_DEPTH: u8 = 8;
// Maximum bounds to prevent OOM on untrusted proofs.
// Arena: 2^22 blocks = 256 MiB arena (2x headroom over MAXIMUM tier 2^21).
// Steps: 2^24 (2x headroom over MAXIMUM tier 4*2^21 = 2^23).
const MAX_ARENA_BLOCKS: u32 = 1 << 22;
const MAX_TOTAL_STEPS: u32 = 1 << 24;

impl PosmeParams {
    /// Validate parameters against minimum bounds.
    pub fn validate(&self) -> Result<()> {
        if self.arena_blocks < MIN_ARENA_BLOCKS {
            return Err(PosmeError::InvalidParams(format!(
                "arena_blocks {} < minimum {MIN_ARENA_BLOCKS}",
                self.arena_blocks
            )));
        }
        if self.arena_blocks > MAX_ARENA_BLOCKS {
            return Err(PosmeError::InvalidParams(format!(
                "arena_blocks {} > maximum {MAX_ARENA_BLOCKS}",
                self.arena_blocks
            )));
        }
        if !self.arena_blocks.is_power_of_two() {
            return Err(PosmeError::InvalidParams(format!(
                "arena_blocks {} must be a power of 2",
                self.arena_blocks
            )));
        }
        if self.total_steps < self.arena_blocks {
            return Err(PosmeError::InvalidParams(format!(
                "total_steps {} < arena_blocks {} (rho must be >= 1)",
                self.total_steps, self.arena_blocks
            )));
        }
        if self.total_steps > MAX_TOTAL_STEPS {
            return Err(PosmeError::InvalidParams(format!(
                "total_steps {} > maximum {MAX_TOTAL_STEPS}",
                self.total_steps
            )));
        }
        if self.reads_per_step < MIN_READS_PER_STEP {
            return Err(PosmeError::InvalidParams(format!(
                "reads_per_step {} < minimum {MIN_READS_PER_STEP}",
                self.reads_per_step
            )));
        }
        if self.challenges < MIN_CHALLENGES {
            return Err(PosmeError::InvalidParams(format!(
                "challenges {} < minimum {MIN_CHALLENGES}",
                self.challenges
            )));
        }
        if u32::from(self.challenges) > self.total_steps {
            return Err(PosmeError::InvalidParams(format!(
                "challenges {} > total_steps {} (pigeonhole: not enough unique steps)",
                self.challenges, self.total_steps
            )));
        }
        if self.recursion_depth < MIN_RECURSION_DEPTH {
            return Err(PosmeError::InvalidParams(format!(
                "recursion_depth {} < minimum {MIN_RECURSION_DEPTH}",
                self.recursion_depth
            )));
        }
        if self.recursion_depth > MAX_RECURSION_DEPTH {
            return Err(PosmeError::InvalidParams(format!(
                "recursion_depth {} > maximum {MAX_RECURSION_DEPTH}",
                self.recursion_depth
            )));
        }
        Ok(())
    }

    /// Write density rho = K/N.
    pub fn rho(&self) -> f64 {
        self.total_steps as f64 / self.arena_blocks as f64
    }

    /// Arena size in bytes.
    pub fn arena_bytes(&self) -> u64 {
        self.arena_blocks as u64 * 64
    }

    /// CORE tier: 4 MiB arena, rho=4, d=8, Q=32, R=1. ~50 MiB peak RAM.
    pub fn core() -> Self {
        Self {
            arena_blocks: 1 << 16,
            total_steps: 4 * (1 << 16),
            reads_per_step: 8,
            challenges: 32,
            recursion_depth: 1,
        }
    }

    /// STANDARD tier: 16 MiB arena, rho=4, d=8, Q=48, R=1. ~150 MiB peak RAM.
    pub fn standard() -> Self {
        Self {
            arena_blocks: 1 << 18,
            total_steps: 4 * (1 << 18),
            reads_per_step: 8,
            challenges: 48,
            recursion_depth: 1,
        }
    }

    /// ENHANCED tier: 64 MiB arena, rho=4, d=8, Q=64, R=2. ~500 MiB peak RAM.
    pub fn enhanced() -> Self {
        Self {
            arena_blocks: 1 << 20,
            total_steps: 4 * (1 << 20),
            reads_per_step: 8,
            challenges: 64,
            recursion_depth: 2,
        }
    }

    /// MAXIMUM tier: 128 MiB arena, rho=4, d=8, Q=128, R=3. ~900 MiB peak RAM.
    pub fn maximum() -> Self {
        Self {
            arena_blocks: 1 << 21,
            total_steps: 4 * (1 << 21),
            reads_per_step: 8,
            challenges: 128,
            recursion_depth: 3,
        }
    }

    /// Select tier by content tier (1=core, 2=standard, 3=enhanced, 4=maximum).
    pub fn for_tier(tier: u8) -> Result<Self> {
        match tier {
            1 => Ok(Self::core()),
            2 => Ok(Self::standard()),
            3 => Ok(Self::enhanced()),
            4 => Ok(Self::maximum()),
            _ => Err(PosmeError::InvalidParams(format!(
                "tier {tier} out of range [1, 4]"
            ))),
        }
    }

    /// Deterministic byte encoding of all parameters for Fiat-Shamir binding.
    /// Layout: N (4B) || K (4B) || d (1B) || Q (2B) || R (1B) = 12 bytes.
    pub fn to_challenge_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.arena_blocks.to_be_bytes());
        buf[4..8].copy_from_slice(&self.total_steps.to_be_bytes());
        buf[8] = self.reads_per_step;
        buf[9..11].copy_from_slice(&self.challenges.to_be_bytes());
        buf[11] = self.recursion_depth;
        buf
    }

    /// Small parameters for testing (fast execution).
    pub fn test() -> Self {
        Self {
            arena_blocks: 1 << 10,
            total_steps: 4 * (1 << 10),
            reads_per_step: 4,
            challenges: 4,
            recursion_depth: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_valid() {
        assert!(PosmeParams::test().validate().is_ok());
        assert!(PosmeParams::core().validate().is_ok());
        assert!(PosmeParams::standard().validate().is_ok());
        assert!(PosmeParams::enhanced().validate().is_ok());
        assert!(PosmeParams::maximum().validate().is_ok());
    }

    #[test]
    fn test_params_rho() {
        let p = PosmeParams::core();
        assert!((p.rho() - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_params_arena_bytes() {
        let p = PosmeParams::core();
        assert_eq!(p.arena_bytes(), 4 * 1024 * 1024); // 4 MiB
    }

    #[test]
    fn reject_non_power_of_two() {
        let mut p = PosmeParams::test();
        p.arena_blocks = 1025;
        assert!(p.validate().is_err());
    }

    #[test]
    fn reject_rho_below_one() {
        let mut p = PosmeParams::test();
        p.total_steps = p.arena_blocks - 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn reject_total_steps_above_max() {
        let mut p = PosmeParams::test();
        p.total_steps = (1 << 24) + 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn reject_challenges_exceed_total_steps() {
        let mut p = PosmeParams::test();
        p.challenges = (p.total_steps + 1) as u16;
        assert!(p.validate().is_err());
    }

    #[test]
    fn reject_arena_blocks_above_max() {
        let mut p = PosmeParams::test();
        p.arena_blocks = 1 << 23; // exceeds MAX_ARENA_BLOCKS (1 << 22)
        p.total_steps = p.arena_blocks; // satisfy rho >= 1
        assert!(p.validate().is_err());
    }
}
