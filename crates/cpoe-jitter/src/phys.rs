// SPDX-License-Identifier: Apache-2.0

//! Hardware-based entropy source using TSC/CNTVCT timing measurements.

use sha2::{Digest, Sha256};

use crate::{EntropySource, Error, Jitter, JitterEngine, PhysHash};

/// Number of timing samples captured per entropy estimation.
const SAMPLE_COUNT: usize = 256;
/// Maximum number of inter-sample deltas.
const MAX_DELTAS: usize = SAMPLE_COUNT - 1;
/// Maximum quantization bins for entropy estimation. Sized so the
/// Markov transition matrix fits comfortably on the stack (4 KiB at 64²).
const MAX_QUANT_BINS: usize = 64;

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
            jmin: crate::DEFAULT_JITTER_MIN_US,
            range: crate::DEFAULT_JITTER_RANGE_US,
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

    /// Capture timing samples into a caller-provided stack buffer.
    ///
    /// Delegates to [`read_hardware_counter`] on hardware targets, consolidating
    /// all architecture-specific intrinsics (TSC, CNTVCT, memory fences) behind
    /// a single abstraction point. On software-only builds, mixes `getrandom`
    /// kernel entropy with timing measurements.
    #[cfg(feature = "hardware")]
    fn capture_timing_samples(&self, out: &mut [u64; SAMPLE_COUNT]) -> Result<(), Error> {
        for s in out.iter_mut() {
            *s = read_hardware_counter();
        }
        Ok(())
    }

    #[cfg(not(feature = "hardware"))]
    fn capture_timing_samples(&self, out: &mut [u64; SAMPLE_COUNT]) -> Result<(), Error> {
        use std::time::Instant;

        let start = Instant::now();

        let mut kernel_entropy = [0u8; 8];
        getrandom::fill(&mut kernel_entropy).map_err(|e| Error::HardwareUnavailable {
            reason: format!("getrandom failed: {}", e),
        })?;
        let kernel_seed = u64::from_le_bytes(kernel_entropy);

        for (i, s) in out.iter_mut().enumerate() {
            let timing = start.elapsed().as_nanos() as u64;
            // Minimal mixing: XOR with a sequential counter provides only trivial
            // diffusion. Entropy quality depends primarily on kernel_seed.
            let varied_seed = kernel_seed ^ (i as u64);
            *s = timing ^ varied_seed;

            std::hint::spin_loop();

            core::hint::black_box(timing);
        }

        Ok(())
    }

    /// Estimate min-entropy (H_∞) of timing samples using multiple estimators
    /// per NIST SP 800-90B §6.3 (non-IID track), returning the minimum as a
    /// conservative bound.
    ///
    /// All intermediate buffers are stack-allocated:
    /// - Deltas: `[i64; MAX_DELTAS]` (≈ 2 KiB)
    /// - Quantized bins: `[u8; MAX_DELTAS]` (255 B)
    /// - MCV frequencies: `[u16; MAX_QUANT_BINS]` (128 B)
    /// - Markov transitions: `[u8; MAX_QUANT_BINS²]` (4 KiB)
    ///
    /// Total stack footprint: ≈ 6.4 KiB, constant regardless of input.
    fn estimate_min_entropy(&self, samples: &[u64]) -> u8 {
        const MAX_ENTROPY_BITS: u8 = 64;

        if samples.len() < 2 {
            return 0;
        }

        let n_deltas = (samples.len() - 1).min(MAX_DELTAS);

        // Stack-allocated deltas.
        let mut delta_buf = [0i64; MAX_DELTAS];
        for i in 0..n_deltas {
            delta_buf[i] = samples[i + 1].wrapping_sub(samples[i]) as i64;
        }
        let deltas = &delta_buf[..n_deltas];

        // Health test: coarse timer produces duplicate timestamps.
        let zero_count = deltas.iter().filter(|&&d| d == 0).count();
        if zero_count > deltas.len() / 10 {
            return 0;
        }

        // Health test: repetition count (SP 800-90B §4.4.1).
        // C = 1 + ⌈-log2(α) / H⌉ with α = 2⁻²⁰, H = 1 → C = 21.
        if max_consecutive_run(deltas) >= 21 {
            return 0;
        }

        // Quantize deltas into uniform-width bins (stack-allocated output).
        let mut bin_buf = [0u8; MAX_DELTAS];
        let n_bins = adaptive_quantize_into(deltas, &mut bin_buf[..n_deltas]);
        let bins = &bin_buf[..n_deltas];

        // Most Common Value estimate (SP 800-90B §6.3.1).
        let h_mcv = mcv_min_entropy_arr(bins);

        // Lag-1 Markov estimate (SP 800-90B §6.3.3).
        let h_markov = markov_min_entropy_arr(bins, n_bins);

        let h_min = h_mcv.min(h_markov);

        if h_min < 1.0 {
            0
        } else {
            (h_min.floor() as u8)
                .saturating_sub(1)
                .min(MAX_ENTROPY_BITS)
        }
    }
}

impl EntropySource for PhysJitter {
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error> {
        let mut samples = [0u64; SAMPLE_COUNT];
        self.capture_timing_samples(&mut samples)?;
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

/// Quantize deltas into uniform-width bins, writing results to `out`.
/// Uses sqrt(n) bins (clamped to [8, MAX_QUANT_BINS]) for balanced frequency
/// estimation. Returns the number of distinct bin slots used.
///
/// All output values are in `0..MAX_QUANT_BINS` so they can directly index
/// the stack-allocated frequency and transition arrays.
fn adaptive_quantize_into(deltas: &[i64], out: &mut [u8]) -> usize {
    debug_assert!(out.len() >= deltas.len());
    if deltas.is_empty() {
        return 0;
    }
    let lo = *deltas.iter().min().unwrap() as i128;
    let hi = *deltas.iter().max().unwrap() as i128;
    if lo == hi {
        for b in out[..deltas.len()].iter_mut() {
            *b = 0;
        }
        return 1;
    }
    let range = (hi - lo) as u128;
    let n_bins = (deltas.len() as f64)
        .sqrt()
        .ceil()
        .clamp(8.0, MAX_QUANT_BINS as f64) as u128;
    let bin_width = (range / n_bins).max(1);
    for (i, &d) in deltas.iter().enumerate() {
        out[i] = ((d as i128 - lo) as u128 / bin_width).min((MAX_QUANT_BINS - 1) as u128) as u8;
    }
    n_bins as usize
}

/// Most Common Value min-entropy estimate (SP 800-90B §6.3.1).
/// H_∞ = -log2(p_max) where p_max = max_freq / n.
///
/// Uses a flat `[u16; MAX_QUANT_BINS]` (128 B) frequency array on the stack
/// instead of a heap-allocated `HashMap`.
fn mcv_min_entropy_arr(bins: &[u8]) -> f64 {
    let mut freq = [0u16; MAX_QUANT_BINS];
    for &b in bins {
        freq[b as usize] += 1;
    }
    let n = bins.len() as f64;
    let p_max = freq.iter().copied().max().unwrap_or(0) as f64 / n;
    if p_max <= 0.0 {
        return 0.0;
    }
    -p_max.log2()
}

/// Lag-1 Markov min-entropy estimate (SP 800-90B §6.3.3).
///
/// Uses a flat `[u8; MAX_QUANT_BINS²]` transition matrix on the stack (4 KiB)
/// instead of nested `HashMap`s. Each cell counts transitions from bin `src`
/// to bin `dst`. With ≤ 255 transitions total, `u8` cannot overflow.
fn markov_min_entropy_arr(bins: &[u8], n_bins: usize) -> f64 {
    if bins.len() < 2 {
        return 0.0;
    }

    let mut transitions = [0u8; MAX_QUANT_BINS * MAX_QUANT_BINS];
    let mut source_counts = [0u16; MAX_QUANT_BINS];

    for w in bins.windows(2) {
        let src = w[0] as usize;
        let dst = w[1] as usize;
        transitions[src * MAX_QUANT_BINS + dst] =
            transitions[src * MAX_QUANT_BINS + dst].saturating_add(1);
        source_counts[src] += 1;
    }

    let mut max_p = 0.0f64;
    let mut had_data = false;
    let scan_bins = n_bins.min(MAX_QUANT_BINS);

    for (src, &src_count) in source_counts.iter().enumerate().take(scan_bins) {
        let total = src_count as usize;
        if total < 4 {
            continue;
        }
        had_data = true;
        let row_start = src * MAX_QUANT_BINS;
        let best = transitions[row_start..row_start + scan_bins]
            .iter()
            .copied()
            .max()
            .unwrap_or(0) as f64;
        let p = best / total as f64;
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
///
/// All architecture-specific intrinsics and memory fences are isolated here
/// so that the rest of the crate remains decoupled from platform target flags.
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
        let samples: Vec<u64> = (0..256)
            .map(|i| if i % 2 == 0 { 0 } else { 1_000_000 })
            .collect();
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
        assert!(
            bits <= 2,
            "4-value cycle should yield ≤ 2 bits, got {}",
            bits
        );
    }

    #[test]
    fn adaptive_quantize_basics() {
        // All identical → all bin 0.
        let mut out = [0u8; 3];
        let n = adaptive_quantize_into(&[5, 5, 5], &mut out);
        assert_eq!(&out, &[0, 0, 0]);
        assert_eq!(n, 1);
        // Two extremes → distinct bins.
        let mut out = [0u8; 2];
        adaptive_quantize_into(&[0, 1000], &mut out);
        assert_ne!(out[0], out[1]);
        // Empty input.
        assert_eq!(adaptive_quantize_into(&[], &mut []), 0);
        // Uniform spread across 16 values → at least 8 distinct bins.
        let deltas: Vec<i64> = (0..16).map(|i| i * 1000).collect();
        let mut out = [0u8; 16];
        adaptive_quantize_into(&deltas, &mut out);
        let unique: std::collections::HashSet<u8> = out.iter().copied().collect();
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
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let delta = 500 + (state >> 48); // 500..66035 range
            acc = acc.wrapping_add(delta);
            samples.push(acc);
        }
        let bits = phys.estimate_min_entropy(&samples);
        assert!(
            bits >= 2,
            "realistic jitter should yield ≥ 2 bits, got {}",
            bits
        );
    }
}
