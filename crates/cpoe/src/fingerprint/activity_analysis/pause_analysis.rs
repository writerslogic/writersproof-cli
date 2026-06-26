// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Characteristic pause patterns (sentence / paragraph / thinking).

use crate::analysis::stats::{merge_histogram, normalize_histogram, relative_similarity};
use serde::{Deserialize, Serialize};

use crate::fingerprint::activity::{weighted_blend, WeightedDistribution};

pub(in crate::fingerprint) const SENTENCE_PAUSE_MS: f64 = 400.0;
pub(in crate::fingerprint) const PARAGRAPH_PAUSE_MS: f64 = 1000.0;
pub(in crate::fingerprint) const THINKING_PAUSE_MS: f64 = 2000.0;
/// 20 bins, 100ms each, covering 0-2000ms for pause histogram
const PAUSE_HISTOGRAM_BUCKETS: usize = 20;
const PAUSE_BUCKET_WIDTH_MS: f64 = 100.0;

/// Characteristic pause patterns (sentence / paragraph / thinking).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseSignature {
    /// Mean duration in ms for each pause tier
    pub sentence_pause_mean: f64,
    pub paragraph_pause_mean: f64,
    pub thinking_pause_mean: f64,
    /// Occurrences per 100 keystrokes
    pub sentence_pause_frequency: f64,
    pub paragraph_pause_frequency: f64,
    pub thinking_pause_frequency: f64,
    /// 20-bin histogram (100ms buckets, 0-2000ms), normalized
    #[serde(default)]
    pub pause_histogram: Vec<f64>,
}

impl Default for PauseSignature {
    fn default() -> Self {
        Self {
            sentence_pause_mean: 0.0,
            paragraph_pause_mean: 0.0,
            thinking_pause_mean: 0.0,
            sentence_pause_frequency: 0.0,
            paragraph_pause_frequency: 0.0,
            thinking_pause_frequency: 0.0,
            pause_histogram: Vec::new(),
        }
    }
}

impl PauseSignature {
    /// Build from IKI values, classifying pauses by duration tier.
    pub fn from_intervals(intervals: &[f64]) -> Self {
        if intervals.is_empty() {
            return Self::default();
        }

        // Filter non-finite values to prevent NaN/Inf from inflating the
        // denominator without contributing to any pause category.
        let intervals: Vec<f64> = intervals
            .iter()
            .copied()
            .filter(|x| x.is_finite())
            .collect();
        if intervals.is_empty() {
            return Self::default();
        }

        let mut sentence_pauses = Vec::new();
        let mut paragraph_pauses = Vec::new();
        let mut thinking_pauses = Vec::new();

        for &iki in &intervals {
            if iki >= THINKING_PAUSE_MS {
                thinking_pauses.push(iki);
            } else if iki >= PARAGRAPH_PAUSE_MS {
                paragraph_pauses.push(iki);
            } else if iki >= SENTENCE_PAUSE_MS {
                sentence_pauses.push(iki);
            }
        }

        let n = intervals.len() as f64;
        let per_100 = 100.0 / n;

        // Build 20-bin pause histogram (100ms buckets, 0-2000ms) from pauses only
        let mut pause_histogram = vec![0.0; PAUSE_HISTOGRAM_BUCKETS];
        for &iki in &intervals {
            if iki >= SENTENCE_PAUSE_MS {
                let bucket =
                    ((iki / PAUSE_BUCKET_WIDTH_MS) as usize).min(PAUSE_HISTOGRAM_BUCKETS - 1);
                pause_histogram[bucket] += 1.0;
            }
        }
        normalize_histogram(&mut pause_histogram);

        Self {
            sentence_pause_mean: crate::utils::stats::mean(&sentence_pauses),
            paragraph_pause_mean: crate::utils::stats::mean(&paragraph_pauses),
            thinking_pause_mean: crate::utils::stats::mean(&thinking_pauses),
            sentence_pause_frequency: sentence_pauses.len() as f64 * per_100,
            paragraph_pause_frequency: paragraph_pauses.len() as f64 * per_100,
            thinking_pause_frequency: thinking_pauses.len() as f64 * per_100,
            pause_histogram,
        }
    }

    /// Weighted merge with another signature.
    pub fn merge(&mut self, other: &PauseSignature, self_weight: f64, other_weight: f64) {
        self.weighted_merge(other, self_weight, other_weight);
    }

    /// Similarity (0.0-1.0) comparing mean durations and frequencies.
    pub fn similarity(&self, other: &PauseSignature) -> f64 {
        <Self as WeightedDistribution>::similarity(self, other)
    }
}

impl WeightedDistribution for PauseSignature {
    fn similarity(&self, other: &Self) -> f64 {
        let mean_sims = [
            relative_similarity(self.sentence_pause_mean, other.sentence_pause_mean),
            relative_similarity(self.paragraph_pause_mean, other.paragraph_pause_mean),
            relative_similarity(self.thinking_pause_mean, other.thinking_pause_mean),
        ];
        let freq_sims = [
            relative_similarity(
                self.sentence_pause_frequency,
                other.sentence_pause_frequency,
            ),
            relative_similarity(
                self.paragraph_pause_frequency,
                other.paragraph_pause_frequency,
            ),
            relative_similarity(
                self.thinking_pause_frequency,
                other.thinking_pause_frequency,
            ),
        ];

        let mean_sim: f64 = mean_sims.iter().sum::<f64>() / 3.0;
        let freq_sim: f64 = freq_sims.iter().sum::<f64>() / 3.0;
        let tier_sim = mean_sim * 0.5 + freq_sim * 0.5;

        // Blend with histogram Bhattacharyya coefficient if both sides have data
        if !self.pause_histogram.is_empty() && !other.pause_histogram.is_empty() {
            let hist_sim = crate::analysis::stats::bhattacharyya_coefficient(
                &self.pause_histogram,
                &other.pause_histogram,
            );
            let hist_sim = if hist_sim.is_finite() { hist_sim } else { 0.5 };
            crate::utils::Probability::clamp(tier_sim * 0.5 + hist_sim * 0.5).get()
        } else {
            crate::utils::Probability::clamp(tier_sim).get()
        }
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        self.sentence_pause_mean = weighted_blend(
            self.sentence_pause_mean,
            other.sentence_pause_mean,
            self_weight,
            other_weight,
        );
        self.paragraph_pause_mean = weighted_blend(
            self.paragraph_pause_mean,
            other.paragraph_pause_mean,
            self_weight,
            other_weight,
        );
        self.thinking_pause_mean = weighted_blend(
            self.thinking_pause_mean,
            other.thinking_pause_mean,
            self_weight,
            other_weight,
        );
        self.sentence_pause_frequency = weighted_blend(
            self.sentence_pause_frequency,
            other.sentence_pause_frequency,
            self_weight,
            other_weight,
        );
        self.paragraph_pause_frequency = weighted_blend(
            self.paragraph_pause_frequency,
            other.paragraph_pause_frequency,
            self_weight,
            other_weight,
        );
        self.thinking_pause_frequency = weighted_blend(
            self.thinking_pause_frequency,
            other.thinking_pause_frequency,
            self_weight,
            other_weight,
        );

        if self.pause_histogram.is_empty() && !other.pause_histogram.is_empty() {
            self.pause_histogram = other.pause_histogram.clone();
        } else if !other.pause_histogram.is_empty() {
            merge_histogram(
                &mut self.pause_histogram,
                &other.pause_histogram,
                self_weight,
                other_weight,
            );
        }
    }
}
