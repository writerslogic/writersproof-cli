// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Keystroke timing entropy validation for detecting low-entropy inputs (paste, transcription, replay).
//!
//! Measures entropy from:
//! - Inter-keystroke intervals (IKI) variance
//! - Jitter distribution within bursts
//! - Recovery from sleep/wake cycles
//! - Timing consistency across keystroke sequences
//!
//! Minimum threshold: 1.5 bits per keystroke (configurable).
//! Low entropy detection flags: transcription, paste injection, replay attacks.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Named constant for minimum acceptable entropy (bits per keystroke).
pub const MIN_ENTROPY_BITS_DEFAULT: f64 = 1.5;

/// Named constant for entropy sample window size (recent keystrokes to analyze).
pub const ENTROPY_SAMPLE_WINDOW_DEFAULT: usize = 50;

/// Named constant for inter-keystroke interval in milliseconds (typical human typing).
pub const IKI_MEAN_TYPICAL_MS: f64 = 150.0;

/// Named constant for minimum inter-keystroke variance coefficient (CV).
pub const IKI_MIN_VARIANCE_CV: f64 = 0.15;

/// Named constant for maximum allowable inter-keystroke time (before gap = sleep).
pub const IKI_MAX_NORMAL_MS: f64 = 5000.0;

/// Keystroke timing sample for entropy calculation.
#[derive(Debug, Clone, Copy)]
pub struct KeystrokeSample {
    /// Timestamp in nanoseconds since epoch.
    pub timestamp_ns: i64,
    /// Key code (for distinguishing patterns).
    pub key_code: u16,
    /// Is this keystroke part of a burst (continuous typing)?
    pub is_burst: bool,
}

/// Entropy validator: measures keystroke timing entropy and detects low-entropy patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyValidator {
    /// Minimum acceptable entropy in bits per keystroke.
    pub min_entropy_bits: f64,
    /// Number of recent keystrokes to analyze.
    pub sample_window: usize,
}

impl EntropyValidator {
    /// Create a new entropy validator with default thresholds.
    pub fn new() -> Self {
        Self {
            min_entropy_bits: MIN_ENTROPY_BITS_DEFAULT,
            sample_window: ENTROPY_SAMPLE_WINDOW_DEFAULT,
        }
    }

    /// Create a new entropy validator with custom thresholds.
    pub fn with_config(min_entropy_bits: f64, sample_window: usize) -> Result<Self> {
        if !(0.0..=10.0).contains(&min_entropy_bits) {
            return Err(Error::validation(format!(
                "min_entropy_bits must be 0.0-10.0, got {}",
                min_entropy_bits
            )));
        }
        if !(10..=1000).contains(&sample_window) {
            return Err(Error::validation(format!(
                "sample_window must be 10-1000, got {}",
                sample_window
            )));
        }
        Ok(Self {
            min_entropy_bits,
            sample_window,
        })
    }

    /// Measure entropy from a sequence of keystroke samples.
    ///
    /// Returns: (entropy_bits_per_keystroke, entropy_assessment)
    /// entropy_bits: Shannon entropy of inter-keystroke interval distribution
    /// assessment: "high", "medium", "low", "critical" based on threshold
    pub fn measure_entropy(&self, samples: &VecDeque<KeystrokeSample>) -> (f64, EntropyAssessment) {
        if samples.len() < 2 {
            // Insufficient data; cannot measure entropy
            return (0.0, EntropyAssessment::InsufficientData);
        }

        let window_size = self.sample_window.min(samples.len());
        let window_samples: Vec<_> = samples
            .iter()
            .rev()
            .take(window_size)
            .rev()
            .copied()
            .collect();

        // Extract inter-keystroke intervals (IKI) in milliseconds
        let mut ikis_ms = Vec::new();
        for i in 1..window_samples.len() {
            let iki_ns = window_samples[i].timestamp_ns - window_samples[i - 1].timestamp_ns;
            let iki_ms = iki_ns as f64 / 1_000_000.0;

            // Skip sleep gaps (> 5 seconds = 5000ms)
            if iki_ms > IKI_MAX_NORMAL_MS {
                continue;
            }

            ikis_ms.push(iki_ms);
        }

        if ikis_ms.is_empty() {
            return (0.0, EntropyAssessment::InsufficientData);
        }

        // Calculate statistics
        let mean_iki = ikis_ms.iter().sum::<f64>() / ikis_ms.len() as f64;
        let variance =
            ikis_ms.iter().map(|x| (x - mean_iki).powi(2)).sum::<f64>() / ikis_ms.len() as f64;
        let std_dev = variance.sqrt();
        let cv = std_dev / mean_iki;

        // Calculate Shannon entropy from IKI distribution
        let entropy = self.calculate_shannon_entropy(&ikis_ms);

        // Assess based on entropy and variance
        let assessment = self.assess_entropy(entropy, cv, mean_iki);

        (entropy, assessment)
    }

    /// Calculate Shannon entropy from a distribution of values.
    ///
    /// Bins values into 10 buckets, computes probability distribution,
    /// then calculates H = -Σ(p_i * log2(p_i))
    fn calculate_shannon_entropy(&self, values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let min_val = values.iter().copied().fold(f64::INFINITY, f64::min);
        let max_val = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        if (max_val - min_val).abs() < 1e-6 {
            // All values identical = zero entropy
            return 0.0;
        }

        // Create 10 bins
        const BINS: usize = 10;
        let bin_width = (max_val - min_val) / BINS as f64;
        let mut counts = vec![0; BINS];

        for &val in values {
            let bin_idx = ((val - min_val) / bin_width).floor() as usize;
            if bin_idx < BINS {
                counts[bin_idx] += 1;
            }
        }

        // Calculate Shannon entropy
        let total = values.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Assess entropy quality based on entropy value, coefficient of variation, and mean IKI.
    fn assess_entropy(&self, entropy: f64, cv: f64, mean_iki: f64) -> EntropyAssessment {
        // Low entropy: below threshold bits
        if entropy < self.min_entropy_bits {
            return EntropyAssessment::Critical;
        }

        // Check coefficient of variation (CV)
        // Low CV (<15%) = monotonic/consistent timing = transcription/paste indicator
        if cv < IKI_MIN_VARIANCE_CV {
            return EntropyAssessment::Low;
        }

        // Check mean IKI reasonableness
        // Very fast typing (< 50ms mean) or very slow (> 2000ms mean) = suspicious
        if !(50.0..=2000.0).contains(&mean_iki) {
            return EntropyAssessment::Low;
        }

        // Entropy in normal range
        if entropy >= self.min_entropy_bits + 1.0 {
            EntropyAssessment::High
        } else {
            EntropyAssessment::Medium
        }
    }

    /// Detect if a sequence shows signs of low-entropy patterns.
    ///
    /// Returns list of detected patterns:
    /// - "monotonic_timing": All inter-keystroke times nearly equal
    /// - "zero_variance_windows": Multiple 500ms windows with <5ms variance
    /// - "rapid_burst": Sustained >300 WPM typing (inhuman speed)
    /// - "discontinuous_gaps": Abnormal silence then immediate recovery
    pub fn detect_low_entropy_patterns(&self, samples: &VecDeque<KeystrokeSample>) -> Vec<String> {
        let mut patterns = Vec::new();

        if samples.len() < 5 {
            return patterns; // Insufficient data
        }

        // Extract IKIs
        let mut ikis_ms = Vec::new();
        for i in 1..samples.len() {
            let iki_ns = samples[i].timestamp_ns - samples[i - 1].timestamp_ns;
            let iki_ms = iki_ns as f64 / 1_000_000.0;
            if iki_ms <= IKI_MAX_NORMAL_MS {
                ikis_ms.push(iki_ms);
            }
        }

        if ikis_ms.len() < 3 {
            return patterns;
        }

        // Pattern 1: Monotonic timing (all IKIs nearly equal)
        let mean = ikis_ms.iter().sum::<f64>() / ikis_ms.len() as f64;
        let variance =
            ikis_ms.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / ikis_ms.len() as f64;
        let std_dev = variance.sqrt();

        if std_dev < mean * 0.05 {
            // <5% standard deviation = monotonic
            patterns.push("monotonic_timing".to_string());
        }

        // Pattern 2: Zero-variance windows (500ms with <5ms std dev)
        let window_ms = 500.0;
        let mut i = 0;
        while i < samples.len() - 1 {
            let start_time = samples[i].timestamp_ns;
            let window_ikis: Vec<f64> = samples
                .iter()
                .skip(i + 1)
                .take_while(|s| (s.timestamp_ns - start_time) as f64 / 1_000_000.0 < window_ms)
                .zip(samples.iter().skip(i))
                .map(|(curr, prev)| (curr.timestamp_ns - prev.timestamp_ns) as f64 / 1_000_000.0)
                .collect();

            if window_ikis.len() > 3 {
                let w_mean = window_ikis.iter().sum::<f64>() / window_ikis.len() as f64;
                let w_var = window_ikis
                    .iter()
                    .map(|x| (x - w_mean).powi(2))
                    .sum::<f64>()
                    / window_ikis.len() as f64;
                let w_std = w_var.sqrt();

                if w_std < 5.0 {
                    // < 5ms std dev in window
                    patterns.push("zero_variance_windows".to_string());
                    break; // Count once
                }
            }

            i += 1;
        }

        // Pattern 3: Rapid burst (>300 WPM sustained)
        // 300 WPM = 1500 CPM = 25 keystrokes/sec = 40ms mean IKI
        if mean < 40.0 {
            patterns.push("rapid_burst".to_string());
        }

        // Pattern 4: Discontinuous gaps followed by immediate recovery
        let mut gap_indices = Vec::new();
        for (i, &iki) in ikis_ms.iter().enumerate() {
            if iki > 1000.0 {
                // Gap > 1 second
                gap_indices.push(i);
            }
        }

        for &gap_idx in &gap_indices {
            if gap_idx > 0 && gap_idx < ikis_ms.len() - 1 {
                let pre_gap = ikis_ms[gap_idx - 1];
                let post_gap = ikis_ms[gap_idx + 1];

                // If pre-gap is normal but post-gap resumes at same speed, suspicious
                if pre_gap > 50.0 && pre_gap < 500.0 && (post_gap - pre_gap).abs() < 50.0 {
                    patterns.push("discontinuous_gaps".to_string());
                    break;
                }
            }
        }

        patterns
    }
}

impl Default for EntropyValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Assessment of keystroke timing entropy quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyAssessment {
    /// Entropy far above threshold; normal human typing.
    High,
    /// Entropy slightly above threshold; acceptable.
    Medium,
    /// Entropy below threshold; possible transcription/paste.
    Low,
    /// Entropy critically low; almost certainly non-human input.
    Critical,
    /// Insufficient keystroke samples to assess.
    InsufficientData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_validator_creation() {
        let validator = EntropyValidator::new();
        assert_eq!(validator.min_entropy_bits, MIN_ENTROPY_BITS_DEFAULT);
        assert_eq!(validator.sample_window, ENTROPY_SAMPLE_WINDOW_DEFAULT);
    }

    #[test]
    fn test_entropy_validator_with_config_valid() {
        let validator = EntropyValidator::with_config(2.0, 100).unwrap();
        assert_eq!(validator.min_entropy_bits, 2.0);
        assert_eq!(validator.sample_window, 100);
    }

    #[test]
    fn test_entropy_validator_with_config_invalid_entropy() {
        let result = EntropyValidator::with_config(15.0, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_validator_with_config_invalid_window() {
        let result = EntropyValidator::with_config(1.5, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_measure_entropy_insufficient_data() {
        let validator = EntropyValidator::new();
        let mut samples = VecDeque::new();
        samples.push_back(KeystrokeSample {
            timestamp_ns: 1000,
            key_code: 65,
            is_burst: true,
        });

        let (entropy, assessment) = validator.measure_entropy(&samples);
        assert_eq!(entropy, 0.0);
        assert_eq!(assessment, EntropyAssessment::InsufficientData);
    }

    #[test]
    fn test_measure_entropy_monotonic_timing() {
        let validator = EntropyValidator::new();
        let mut samples = VecDeque::new();

        // Add keystrokes with identical inter-keystroke intervals (100ms)
        let mut timestamp = 0i64;
        for _i in 0..20 {
            samples.push_back(KeystrokeSample {
                timestamp_ns: timestamp,
                key_code: 65,
                is_burst: true,
            });
            timestamp += 100_000_000; // 100ms intervals
        }

        let (_entropy, assessment) = validator.measure_entropy(&samples);
        assert_eq!(assessment, EntropyAssessment::Critical);
    }

    #[test]
    fn test_measure_entropy_variable_timing() {
        let validator = EntropyValidator::new();
        let mut samples = VecDeque::new();

        // Add keystrokes with variable intervals (80-200ms)
        let mut timestamp = 0i64;
        let intervals_ns = [
            80_000_000,
            150_000_000,
            120_000_000,
            200_000_000,
            100_000_000,
            180_000_000,
            90_000_000,
            160_000_000,
            110_000_000,
            190_000_000,
            95_000_000,
            170_000_000,
            105_000_000,
            185_000_000,
            115_000_000,
        ];

        for &interval in &intervals_ns {
            samples.push_back(KeystrokeSample {
                timestamp_ns: timestamp,
                key_code: 65,
                is_burst: true,
            });
            timestamp += interval;
        }

        let (entropy, assessment) = validator.measure_entropy(&samples);
        assert!(entropy > 0.0);
        assert!(matches!(
            assessment,
            EntropyAssessment::High | EntropyAssessment::Medium
        ));
    }

    #[test]
    fn test_detect_low_entropy_patterns_monotonic() {
        let validator = EntropyValidator::new();
        let mut samples = VecDeque::new();

        // Monotonic timing
        let mut timestamp = 0i64;
        for _ in 0..20 {
            samples.push_back(KeystrokeSample {
                timestamp_ns: timestamp,
                key_code: 65,
                is_burst: true,
            });
            timestamp += 100_000_000; // Exactly 100ms
        }

        let patterns = validator.detect_low_entropy_patterns(&samples);
        assert!(patterns.contains(&"monotonic_timing".to_string()));
    }

    #[test]
    fn test_detect_low_entropy_patterns_rapid_burst() {
        let validator = EntropyValidator::new();
        let mut samples = VecDeque::new();

        // Inhuman typing speed: 30ms intervals = 33 keys/sec = 400 WPM
        let mut timestamp = 0i64;
        for _ in 0..20 {
            samples.push_back(KeystrokeSample {
                timestamp_ns: timestamp,
                key_code: 65,
                is_burst: true,
            });
            timestamp += 30_000_000; // 30ms = inhuman speed
        }

        let patterns = validator.detect_low_entropy_patterns(&samples);
        assert!(patterns.contains(&"rapid_burst".to_string()));
    }

    #[test]
    fn test_shannon_entropy_uniform_distribution() {
        let validator = EntropyValidator::new();
        let values = vec![
            100.0, 200.0, 300.0, 400.0, 500.0, 100.0, 200.0, 300.0, 400.0, 500.0,
        ];
        let entropy = validator.calculate_shannon_entropy(&values);
        assert!(entropy > 0.0);
    }

    #[test]
    fn test_shannon_entropy_identical_values() {
        let validator = EntropyValidator::new();
        let values = vec![150.0; 20];
        let entropy = validator.calculate_shannon_entropy(&values);
        assert_eq!(entropy, 0.0);
    }
}
