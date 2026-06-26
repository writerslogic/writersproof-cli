// SPDX-License-Identifier: Apache-2.0

//! Statistical model for human typing validation (Aalto 136M keystroke baseline).

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use serde::{Deserialize, Serialize};

#[inline]
fn sqrt(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.sqrt()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::sqrt(x)
    }
}

use crate::{Evidence, Jitter};

/// Integer thresholds for deterministic cross-platform comparisons.
/// All anomaly decisions use integer math; f64 is only for display.
///
/// MIN_STD_DEV_THRESHOLD_US (50µs): Minimum jitter standard deviation expected
/// from real hardware timing. Below this, the source lacks physical noise
/// (synthetic or replayed data). Derived from NIST SP 800-90B §3.1.3 minimum
/// entropy requirement applied to µs-resolution timers.
///
/// MIN_IKI_STD_DEV_THRESHOLD_US (5000µs = 5ms): Minimum inter-keystroke interval
/// deviation for human typing. Human typing at ~60 WPM has σ ≈ 30-80ms; at
/// 120 WPM σ ≈ 15-40ms. A threshold of 5ms catches synthetic replay (σ < 1ms)
/// while accepting fast typists. The 100x ratio vs jitter threshold reflects
/// that IKI operates in ms-scale while jitter operates in µs-scale.
///
/// CONFIDENCE_PENALTY_PER_ANOMALY (0.25): Each detected anomaly reduces confidence
/// by 25%. With 4+ anomalies, confidence reaches 0. This linear decay models
/// independent failure modes: 1 anomaly = plausible noise (75%), 2 = suspicious
/// (50%), 3 = likely synthetic (25%), 4+ = reject (0%).
const MIN_STD_DEV_THRESHOLD_US: u64 = 50;
const MIN_IKI_STD_DEV_THRESHOLD_US: u64 = 5000;
const CONFIDENCE_PENALTY_PER_ANOMALY: f64 = 0.25;
const MIN_PATTERN_CHECKS_EXCLUSIVE: usize = 2;
/// Maximum plausible IKI: 10 minutes in microseconds. Values above this
/// are rejected as invalid input rather than silently capped.
const MAX_PLAUSIBLE_IKI_US: u64 = 600_000_000;

/// Statistical model of human typing based on the Aalto 136M keystroke dataset.
///
/// All IKI (inter-keystroke interval) fields are in microseconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanModel {
    /// Minimum plausible IKI (µs). Default: 30 000 (30 ms).
    pub iki_min_us: u32,
    /// Maximum plausible IKI (µs). Default: 2 000 000 (2 s).
    pub iki_max_us: u32,
    /// Expected mean IKI (µs). Default: 200 000 (200 ms, ~60 WPM).
    pub iki_mean_us: u32,
    /// Expected IKI standard deviation (µs). Default: 80 000 (80 ms).
    pub iki_std_us: u32,
    /// Minimum plausible jitter value (µs). Default: 500.
    pub jitter_min_us: u32,
    /// Maximum plausible jitter value (µs). Default: 3000.
    pub jitter_max_us: u32,
    /// Minimum number of samples for meaningful validation.
    pub min_sequence_length: usize,
    /// Maximum fraction of samples with identical timing (0.0–1.0).
    /// Above this threshold an `Anomaly::PerfectTiming` is raised.
    pub max_perfect_ratio: f64,
}

impl Default for HumanModel {
    fn default() -> Self {
        Self {
            iki_min_us: 30_000,
            iki_max_us: 2_000_000,
            iki_mean_us: 200_000,
            iki_std_us: 80_000,
            jitter_min_us: crate::DEFAULT_JITTER_MIN_US,
            jitter_max_us: crate::DEFAULT_JITTER_MAX_US,
            min_sequence_length: 20,
            max_perfect_ratio: 0.05,
        }
    }
}

/// Result of validating a jitter or IKI sequence against a [`HumanModel`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the sequence is consistent with human typing.
    pub is_human: bool,
    /// Confidence score in [0.0, 1.0], reduced by 0.25 per anomaly.
    pub confidence: f64,
    /// Detected anomalies, if any.
    pub anomalies: Vec<Anomaly>,
    /// Descriptive statistics of the input sequence.
    pub stats: SequenceStats,
}

/// A single anomaly detected during validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Category of anomaly.
    pub kind: AnomalyKind,
    /// Index of the first sample that triggered this anomaly.
    pub position: usize,
    /// Human-readable description with counts and thresholds.
    pub detail: String,
}

/// Categories of timing anomalies that indicate non-human input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyKind {
    /// Too many samples share identical timing values.
    PerfectTiming,
    /// Values outside the model's plausible range.
    OutOfRange,
    /// Sequence too short for meaningful analysis.
    InsufficientData,
    /// Detected a short repeating pattern (length 2-5).
    RepeatingPattern,
    /// Standard deviation below the minimum threshold.
    LowVariance,
}

/// Descriptive statistics of a jitter or IKI sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceStats {
    /// Number of samples.
    pub count: usize,
    /// Arithmetic mean (µs).
    pub mean: f64,
    /// Population standard deviation (µs).
    pub std_dev: f64,
    /// Minimum value (µs).
    pub min: Jitter,
    /// Maximum value (µs).
    pub max: Jitter,
}

/// Single-pass out-of-range scan over an iterator returning count and first position
fn out_of_range_anomaly<I, T>(
    values: I,
    pred: impl Fn(&T) -> bool,
    min_label: u64,
    max_label: u64,
    name: &str,
) -> Option<Anomaly>
where
    I: Iterator<Item = T>,
{
    let mut count = 0usize;
    let mut first = 0usize;
    for (i, v) in values.enumerate() {
        if pred(&v) {
            if count == 0 {
                first = i;
            }
            count += 1;
        }
    }
    if count > 0 {
        Some(Anomaly {
            kind: AnomalyKind::OutOfRange,
            position: first,
            detail: format!(
                "{} {} values outside [{}, {}]\u{00b5}s range",
                count, name, min_label, max_label
            ),
        })
    } else {
        None
    }
}

impl HumanModel {
    /// Load the built-in Aalto baseline model.
    #[cfg(feature = "std")]
    pub fn baseline() -> Result<Self, serde_json::Error> {
        const BASELINE: &str = include_str!("baseline.json");
        serde_json::from_str(BASELINE)
    }

    /// Deserialize a model from a JSON string.
    #[cfg(feature = "std")]
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize this model to a pretty-printed JSON string.
    #[cfg(feature = "std")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Validate raw jitter values against this model's thresholds.
    pub fn validate(&self, jitters: &[Jitter]) -> ValidationResult {
        let oor = out_of_range_anomaly(
            jitters.iter().copied(),
            |&j| j < self.jitter_min_us || j > self.jitter_max_us,
            self.jitter_min_us as u64,
            self.jitter_max_us as u64,
            "jitter",
        );
        let (perfect_count, perfect_pairs) = self.compute_perfect_counts_jitters(jitters);
        let pattern = self.detect_repeating_pattern_jitters(jitters);
        let (stats, variance_n2) = self.compute_stats(jitters.iter().copied());
        self.validate_inner(
            jitters.len(),
            stats,
            variance_n2,
            oor,
            perfect_count,
            perfect_pairs,
            pattern,
            MIN_STD_DEV_THRESHOLD_US,
        )
    }

    /// Validate directly from an Evidence slice by extracting jitter values.
    pub fn validate_records(&self, records: &[Evidence]) -> ValidationResult {
        let jitters: Vec<Jitter> = records.iter().map(|e| e.jitter()).collect();
        self.validate(&jitters)
    }

    /// Validate inter-keystroke intervals (µs) against this model's IKI thresholds.
    pub fn validate_iki(&self, intervals_us: &[u64]) -> ValidationResult {
        // Reject implausible IKI values (>10 min) as invalid input.
        if let Some(pos) = intervals_us.iter().position(|&v| v > MAX_PLAUSIBLE_IKI_US) {
            return ValidationResult {
                is_human: false,
                confidence: 0.0,
                anomalies: vec![Anomaly {
                    kind: AnomalyKind::OutOfRange,
                    position: pos,
                    detail: format!(
                        "IKI value {}µs exceeds maximum plausible interval ({}µs)",
                        intervals_us[pos], MAX_PLAUSIBLE_IKI_US
                    ),
                }],
                stats: SequenceStats {
                    count: 0,
                    mean: 0.0,
                    std_dev: 0.0,
                    min: 0,
                    max: 0,
                },
            };
        }
        let oor = out_of_range_anomaly(
            intervals_us.iter().copied(),
            |&iki| iki < self.iki_min_us as u64 || iki > self.iki_max_us as u64,
            self.iki_min_us as u64,
            self.iki_max_us as u64,
            "IKI",
        );
        // Safe cast: all values are <= MAX_PLAUSIBLE_IKI_US (600M) < u32::MAX (4.2B).
        let capped: Vec<u32> = intervals_us.iter().map(|&v| v as u32).collect();

        let (perfect_count, perfect_pairs) = self.compute_perfect_counts_jitters(&capped);
        let pattern = self.detect_repeating_pattern_jitters(&capped);
        let (stats, variance_n2) = self.compute_stats(capped.into_iter());

        self.validate_inner(
            stats.count,
            stats,
            variance_n2,
            oor,
            perfect_count,
            perfect_pairs,
            pattern,
            MIN_IKI_STD_DEV_THRESHOLD_US,
        )
    }

    /// All threshold comparisons use integer arithmetic for cross-platform
    /// determinism. The f64 fields in SequenceStats and confidence are
    /// derived from integer accumulators for display only and do not
    /// influence the is_human verdict.
    #[allow(clippy::too_many_arguments)]
    fn validate_inner(
        &self,
        len: usize,
        stats: SequenceStats,
        variance_n2: u128,
        out_of_range: Option<Anomaly>,
        perfect_count: usize,
        perfect_pairs: usize,
        repeating_pattern_len: Option<usize>,
        std_dev_threshold_us: u64,
    ) -> ValidationResult {
        if len < self.min_sequence_length {
            return ValidationResult {
                is_human: false,
                confidence: 0.0,
                anomalies: vec![Anomaly {
                    kind: AnomalyKind::InsufficientData,
                    position: 0,
                    detail: format!("Sequence too short: {} < {}", len, self.min_sequence_length),
                }],
                stats,
            };
        }

        let mut anomalies = Vec::new();

        // std_dev < threshold ⟺ variance_n2 < (threshold × n)²
        let n = stats.count as u128;
        let threshold_n = std_dev_threshold_us as u128 * n;
        if variance_n2 < threshold_n * threshold_n {
            anomalies.push(Anomaly {
                kind: AnomalyKind::LowVariance,
                position: 0,
                detail: format!("Variance too low: std_dev={:.2}", stats.std_dev),
            });
        }

        // perfect_count / perfect_pairs > max_perfect_ratio
        // ⟺ perfect_count × 10000 > round(max_perfect_ratio × 10000) × perfect_pairs
        if perfect_pairs > 0 {
            let clamped_ratio = self.max_perfect_ratio.clamp(0.0, 1.0);
            let ratio_bps = libm::round(clamped_ratio * 10000.0) as u64;
            if (perfect_count as u64) * 10000 > ratio_bps * (perfect_pairs as u64) {
                let pct = perfect_count as f64 / perfect_pairs as f64 * 100.0;
                anomalies.push(Anomaly {
                    kind: AnomalyKind::PerfectTiming,
                    position: 0,
                    detail: format!("Too many perfect timings: {:.1}%", pct),
                });
            }
        }

        if let Some(pattern_len) = repeating_pattern_len {
            anomalies.push(Anomaly {
                kind: AnomalyKind::RepeatingPattern,
                position: 0,
                detail: format!("Repeating pattern of length {}", pattern_len),
            });
        }

        anomalies.extend(out_of_range);

        let base_confidence = 1.0 - (anomalies.len() as f64 * CONFIDENCE_PENALTY_PER_ANOMALY);
        let confidence = base_confidence.clamp(0.0, 1.0);

        ValidationResult {
            is_human: anomalies.is_empty(),
            confidence,
            anomalies,
            stats,
        }
    }

    /// Returns (display stats, n²×variance) where the u128 is used for
    /// deterministic integer threshold comparisons.
    fn compute_stats<I: Iterator<Item = Jitter>>(&self, jitters: I) -> (SequenceStats, u128) {
        let mut n: u64 = 0;
        let mut sum: u128 = 0;
        let mut sum_sq: u128 = 0;
        let mut lo = u32::MAX;
        let mut hi = 0u32;

        for j in jitters {
            n += 1;
            sum += j as u128;
            sum_sq += (j as u128) * (j as u128);
            if j < lo {
                lo = j;
            }
            if j > hi {
                hi = j;
            }
        }

        if n == 0 {
            return (
                SequenceStats {
                    count: 0,
                    mean: 0.0,
                    std_dev: 0.0,
                    min: 0,
                    max: 0,
                },
                0,
            );
        }

        let nn = n as u128;
        // n * sum_sq - sum² = n² × population_variance (exact integer)
        let variance_n2 = nn * sum_sq - sum * sum;
        let mean = sum as f64 / n as f64;
        let variance = variance_n2 as f64 / (nn * nn) as f64;

        (
            SequenceStats {
                count: n as usize,
                mean,
                std_dev: sqrt(variance.max(0.0)),
                min: lo,
                max: hi,
            },
            variance_n2,
        )
    }

    /// Returns (perfect_count, total_pairs) for integer ratio comparison.
    fn compute_perfect_counts_jitters(&self, jitters: &[Jitter]) -> (usize, usize) {
        let perfect_count = jitters.windows(2).filter(|w| w[0] == w[1]).count();
        let pairs = if jitters.len() > 1 {
            jitters.len() - 1
        } else {
            0
        };
        (perfect_count, pairs)
    }

    fn detect_repeating_pattern_jitters(&self, jitters: &[Jitter]) -> Option<usize> {
        if jitters.len() < 6 {
            return None;
        }

        for pattern_len in 2..=5 {
            if jitters.len() < pattern_len * 3 {
                continue;
            }

            let pattern = &jitters[..pattern_len];
            let mut matches = 0;
            let mut checks = 0;

            for chunk in jitters.chunks(pattern_len) {
                if chunk.len() == pattern_len {
                    checks += 1;
                    if chunk == pattern {
                        matches += 1;
                    }
                }
            }

            // matches / checks > 4/5 ⟺ matches * 5 > checks * 4
            if checks > MIN_PATTERN_CHECKS_EXCLUSIVE && matches * 5 > checks * 4 {
                return Some(pattern_len);
            }
        }
        None
    }
}
