// SPDX-License-Identifier: Apache-2.0

//! Hardware-based entropy source using TSC/CNTVCT timing measurements.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::{EntropySource, Error, Jitter, JitterEngine, PhysHash};

/// Hardware-based jitter engine using TSC/CNTVCT timing measurements.
///
/// Samples physical timing noise from the CPU's high-resolution counter,
/// hashes it with SHA-256, and produces a [`PhysHash`] with estimated entropy bits.
#[derive(Debug, Clone)]
pub struct PhysJitter {
    min_entropy_bits: u8,
    jmin: u32,
    range: u32,
}

impl PhysJitter {
    /// Minimum entropy bits threshold for hardware sampling.
    pub fn min_entropy_bits(&self) -> u8 {
        self.min_entropy_bits
    }

    /// Minimum jitter output in microseconds.
    pub fn jmin(&self) -> u32 {
        self.jmin
    }

    /// Range of jitter values above `jmin`.
    pub fn range(&self) -> u32 {
        self.range
    }
}

impl Default for PhysJitter {
    fn default() -> Self {
        Self {
            min_entropy_bits: 0,
            jmin: 500,
            range: 2500,
        }
    }
}

impl PhysJitter {
    /// Create a `PhysJitter` that requires at least `min_entropy_bits` of entropy per sample.
    pub fn new(min_entropy_bits: u8) -> Self {
        Self {
            min_entropy_bits,
            ..Default::default()
        }
    }

    /// Set the jitter output range.
    ///
    /// Returns `Error::InvalidParameter` if `range` is 0.
    pub fn with_jitter_range(mut self, jmin: u32, range: u32) -> Result<Self, Error> {
        if range == 0 {
            return Err(Error::InvalidParameter("range must be > 0"));
        }
        self.jmin = jmin;
        self.range = range;
        Ok(self)
    }

    /// Set the jitter output range, returning `None` if `range` is 0.
    pub fn try_with_jitter_range(self, jmin: u32, range: u32) -> Option<Self> {
        self.with_jitter_range(jmin, range).ok()
    }

    #[cfg(feature = "hardware")]
    fn capture_timing_samples(&self, count: usize) -> Result<Vec<u64>, Error> {
        let mut samples = Vec::with_capacity(count);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let start = std::time::Instant::now();

        for _ in 0..count {
            #[cfg(target_arch = "x86_64")]
            {
                let tsc: u64;
                // SAFETY: _mm_lfence and _rdtsc are safe CPU intrinsics for reading the timestamp counter
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe {
                    core::arch::x86_64::_mm_lfence();
                    tsc = core::arch::x86_64::_rdtsc();
                    core::arch::x86_64::_mm_lfence();
                }
                samples.push(tsc);
            }

            #[cfg(target_arch = "aarch64")]
            {
                let cntvct: u64;
                // SAFETY: Reading cntvct_el0 is a safe operation to get the virtual timer count
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe {
                    core::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct);
                }
                samples.push(cntvct);
            }

            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                // Limitation: Instant resolution is OS-dependent (often ~1us);
                // tight-loop reads may yield duplicate timestamps, reducing entropy.
                samples.push(start.elapsed().as_nanos() as u64);
            }
        }

        Ok(samples)
    }

    #[cfg(not(feature = "hardware"))]
    fn capture_timing_samples(&self, count: usize) -> Result<Vec<u64>, Error> {
        use std::time::Instant;

        let mut samples = Vec::with_capacity(count);
        let start = Instant::now();

        let mut kernel_entropy = [0u8; 8];
        getrandom::fill(&mut kernel_entropy).map_err(|e| Error::HardwareUnavailable {
            reason: format!("getrandom failed: {}", e),
        })?;
        let kernel_seed = u64::from_le_bytes(kernel_entropy);

        for i in 0..count {
            let timing = start.elapsed().as_nanos() as u64;
            // Minimal mixing: XOR with a sequential counter provides only trivial
            // diffusion. Entropy quality depends primarily on kernel_seed.
            let varied_seed = kernel_seed ^ (i as u64);
            samples.push(timing ^ varied_seed);

            std::hint::spin_loop();

            core::hint::black_box(timing);
        }

        Ok(samples)
    }

    /// Estimate min-entropy (H_∞) of timing samples using multiple estimators
    /// per NIST SP 800-90B §6.3 (non-IID track), returning the minimum as a
    /// conservative bound.
    ///
    /// The previous std-dev estimator was vulnerable to spoofed distributions:
    /// alternating extreme values yield high dispersion but only 1 bit of true
    /// min-entropy. This implementation uses frequency and transition analysis
    /// to measure actual unpredictability.
    fn estimate_min_entropy(&self, samples: &[u64]) -> u8 {
        const MAX_ENTROPY_BITS: u8 = 64;

        if samples.len() < 2 {
            return 0;
        }

        let deltas: Vec<i64> = samples
            .windows(2)
            .map(|w| w[1].wrapping_sub(w[0]) as i64)
            .collect();

        // Health test: coarse timer produces duplicate timestamps.
        let zero_count = deltas.iter().filter(|&&d| d == 0).count();
        if zero_count > deltas.len() / 10 {
            return 0;
        }

        // Health test: repetition count (SP 800-90B §4.4.1).
        // C = 1 + ⌈-log2(α) / H⌉ with α = 2⁻²⁰, H = 1 → C = 21.
        if max_consecutive_run(&deltas) >= 21 {
            return 0;
        }

        // Quantize deltas into uniform-width bins for frequency analysis.
        let bins = adaptive_quantize(&deltas);

        // Most Common Value estimate (SP 800-90B §6.3.1).
        let h_mcv = mcv_min_entropy(&bins);

        // Lag-1 Markov estimate (SP 800-90B §6.3.3).
        let h_markov = markov_min_entropy(&bins);

        let h_min = h_mcv.min(h_markov);

        if h_min < 1.0 {
            0
        } else {
            (h_min.floor() as u8).saturating_sub(1).min(MAX_ENTROPY_BITS)
        }
    }
}

impl EntropySource for PhysJitter {
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error> {
        let samples = self.capture_timing_samples(256)?;
        let entropy_bits = self.estimate_min_entropy(&samples);
        if entropy_bits < self.min_entropy_bits {
            return Err(Error::InsufficientEntropy {
                required: self.min_entropy_bits,
                found: entropy_bits,
            });
        }

        let mut hasher = Sha256::new();
        for sample in &samples {
            hasher.update(sample.to_le_bytes());
        }
        hasher.update(inputs);

        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);

        Ok(PhysHash {
            hash: hash_bytes,
            entropy_bits,
        })
    }

    fn validate(&self, hash: PhysHash) -> bool {
        hash.entropy_bits >= self.min_entropy_bits
    }
}

impl JitterEngine for PhysJitter {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter {
        crate::traits::hmac_jitter(secret, inputs, &entropy.hash, self.jmin, self.range)
    }
}

/// Quantize deltas into uniform-width bins spanning the observed range.
/// Uses sqrt(n) bins (clamped to [8, 128]) for balanced frequency estimation
/// without the concentration artifacts of logarithmic binning.
fn adaptive_quantize(deltas: &[i64]) -> Vec<i32> {
    if deltas.is_empty() {
        return Vec::new();
    }
    let lo = *deltas.iter().min().unwrap() as i128;
    let hi = *deltas.iter().max().unwrap() as i128;
    if lo == hi {
        return vec![0; deltas.len()];
    }
    let range = (hi - lo) as u128;
    let n_bins = (deltas.len() as f64).sqrt().ceil().clamp(8.0, 128.0) as u128;
    let bin_width = (range / n_bins).max(1);
    deltas
        .iter()
        .map(|&d| ((d as i128 - lo) as u128 / bin_width) as i32)
        .collect()
}

/// Most Common Value min-entropy estimate (SP 800-90B §6.3.1).
/// H_∞ = -log2(p_max) where p_max = max_freq / n.
fn mcv_min_entropy(bins: &[i32]) -> f64 {
    let mut freq: HashMap<i32, usize> = HashMap::new();
    for &b in bins {
        *freq.entry(b).or_insert(0) += 1;
    }
    let n = bins.len() as f64;
    let p_max = freq.values().copied().max().unwrap_or(0) as f64 / n;
    if p_max <= 0.0 {
        return 0.0;
    }
    -p_max.log2()
}

/// Lag-1 Markov min-entropy estimate (SP 800-90B §6.3.3).
///
/// For each bin value with sufficient observations, computes the probability
/// of its most likely successor. Returns -log2 of the worst-case (highest)
/// transition probability. This catches alternating, sequential, and other
/// patterns with strong serial dependencies that MCV alone misses.
fn markov_min_entropy(bins: &[i32]) -> f64 {
    if bins.len() < 2 {
        return 0.0;
    }

    let mut transitions: HashMap<i32, HashMap<i32, usize>> = HashMap::new();
    let mut source_counts: HashMap<i32, usize> = HashMap::new();

    for w in bins.windows(2) {
        *transitions.entry(w[0]).or_default().entry(w[1]).or_insert(0) += 1;
        *source_counts.entry(w[0]).or_insert(0) += 1;
    }

    let mut max_p = 0.0f64;
    let mut had_data = false;

    for (src, successors) in &transitions {
        let total = source_counts[src];
        if total < 4 {
            continue;
        }
        had_data = true;
        let best = *successors.values().max().unwrap_or(&0);
        let p = best as f64 / total as f64;
        if p > max_p {
            max_p = p;
        }
    }

    // Only constrain the estimate when a dominant successor exists.
    // With small per-bin counts (~16), random data yields max_p ≈ 0.25-0.30
    // from sampling noise alone. Requiring > 0.5 ensures we only flag real
    // serial dependencies (alternating, cycles) where one successor dominates.
    if !had_data || max_p <= 0.5 {
        return f64::MAX;
    }

    -max_p.log2()
}

/// Length of the longest consecutive run of identical values.
fn max_consecutive_run(values: &[i64]) -> usize {
    if values.is_empty() {
        return 0;
    }
    let mut max_run = 1usize;
    let mut run = 1usize;
    for w in values.windows(2) {
        if w[0] == w[1] {
            run += 1;
            if run > max_run {
                max_run = run;
            }
        } else {
            run = 1;
        }
    }
    max_run
}

/// Read the CPU's high-resolution hardware counter (TSC on x86_64, CNTVCT on
/// aarch64, or nanoseconds since process start on other platforms).
///
/// Used by [`crate::evidence::KeystrokeBindingChain`] to bind each keystroke
/// to the hardware counter at the moment it fires, creating a causal chain
/// that cannot be reordered or synthesized without knowing the counter values.
pub fn read_hardware_counter() -> u64 {
    #[cfg(feature = "hardware")]
    {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: _mm_lfence and _rdtsc are safe CPU intrinsics for reading the TSC.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            core::arch::x86_64::_mm_lfence();
            let tsc = core::arch::x86_64::_rdtsc();
            core::arch::x86_64::_mm_lfence();
            tsc
        }

        #[cfg(target_arch = "aarch64")]
        // SAFETY: mrs cntvct_el0 reads the virtual counter; available to EL0 by default.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let cntvct: u64;
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct);
            cntvct
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            use std::time::Instant;
            static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
            START.get_or_init(Instant::now).elapsed().as_nanos() as u64
        }
    }

    #[cfg(not(feature = "hardware"))]
    {
        use std::time::Instant;
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternating_values_yield_near_zero_entropy() {
        let phys = PhysJitter::new(0);
        // Attacker spoofs TSC to alternate between two extremes.
        let samples: Vec<u64> = (0..256).map(|i| if i % 2 == 0 { 0 } else { 1_000_000 }).collect();
        let bits = phys.estimate_min_entropy(&samples);
        // Markov estimate: each state perfectly predicts the next → 0 bits.
        assert_eq!(bits, 0, "alternating pattern must yield 0 entropy bits");
    }

    #[test]
    fn constant_deltas_yield_zero_entropy() {
        let phys = PhysJitter::new(0);
        // Linear ramp: constant delta = zero entropy.
        let samples: Vec<u64> = (0..256).map(|i| i * 1000).collect();
        let bits = phys.estimate_min_entropy(&samples);
        assert_eq!(bits, 0, "constant-delta sequence must yield 0 entropy bits");
    }

    #[test]
    fn coarse_timer_yields_zero_entropy() {
        let phys = PhysJitter::new(0);
        // All identical timestamps.
        let samples = vec![42u64; 256];
        let bits = phys.estimate_min_entropy(&samples);
        assert_eq!(bits, 0);
    }

    #[test]
    fn short_repeating_pattern_yields_low_entropy() {
        let phys = PhysJitter::new(0);
        // 4-value cycle: predictable from Markov transitions.
        let pattern = [100u64, 300, 900, 50];
        let samples: Vec<u64> = pattern.iter().copied().cycle().take(256).collect();
        let bits = phys.estimate_min_entropy(&samples);
        assert!(bits <= 2, "4-value cycle should yield ≤ 2 bits, got {}", bits);
    }

    #[test]
    fn adaptive_quantize_basics() {
        // All identical → all bin 0.
        assert_eq!(adaptive_quantize(&[5, 5, 5]), vec![0, 0, 0]);
        // Two extremes → distinct bins.
        let bins = adaptive_quantize(&[0, 1000]);
        assert_ne!(bins[0], bins[1]);
        // Empty input.
        assert!(adaptive_quantize(&[]).is_empty());
        // Uniform spread across 16 values → at least 8 distinct bins.
        let deltas: Vec<i64> = (0..16).map(|i| i * 1000).collect();
        let bins = adaptive_quantize(&deltas);
        let unique: std::collections::HashSet<i32> = bins.iter().copied().collect();
        assert!(unique.len() >= 8, "expected ≥ 8 bins, got {}", unique.len());
    }

    #[test]
    fn max_consecutive_run_basic() {
        assert_eq!(max_consecutive_run(&[]), 0);
        assert_eq!(max_consecutive_run(&[1]), 1);
        assert_eq!(max_consecutive_run(&[1, 2, 3]), 1);
        assert_eq!(max_consecutive_run(&[1, 1, 2, 3]), 2);
        assert_eq!(max_consecutive_run(&[1, 2, 2, 2, 3]), 3);
    }

    #[test]
    fn genuine_jitter_passes_entropy_check() {
        let phys = PhysJitter::new(0);
        // Simulate realistic jitter: base value with random-looking perturbation.
        // Uses a simple LCG to generate pseudo-random deltas without pulling in rand.
        let mut samples = Vec::with_capacity(256);
        let mut state: u64 = 0xdeadbeef;
        let mut acc: u64 = 0;
        for _ in 0..256 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let delta = 500 + (state >> 48); // 500..66035 range
            acc = acc.wrapping_add(delta);
            samples.push(acc);
        }
        let bits = phys.estimate_min_entropy(&samples);
        assert!(bits >= 2, "realistic jitter should yield ≥ 2 bits, got {}", bits);
    }
}
