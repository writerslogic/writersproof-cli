// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Distribution types for typing dynamics analysis: IKI, zone profiles, pause signatures,
//! circadian patterns, and session signatures.

use std::collections::HashMap;

use crate::analysis::stats;
use crate::analysis::stats::{merge_histogram, normalize_histogram, relative_similarity};
use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

use super::activity::{weighted_blend, WeightedDistribution};

/// 50ms buckets covering 0-2500ms
pub(super) const IKI_HISTOGRAM_BUCKETS: usize = 50;
const IKI_BUCKET_WIDTH_MS: f64 = 50.0;
/// 8x8 zone transition matrix
const ZONE_TRANSITIONS: usize = 64;
pub(super) const SENTENCE_PAUSE_MS: f64 = 400.0;
pub(super) const PARAGRAPH_PAUSE_MS: f64 = 1000.0;
pub(super) const THINKING_PAUSE_MS: f64 = 2000.0;
/// 20 bins, 100ms each, covering 0-2000ms for pause histogram
const PAUSE_HISTOGRAM_BUCKETS: usize = 20;
const PAUSE_BUCKET_WIDTH_MS: f64 = 100.0;
/// IKI threshold for burst detection (ms)
const BURST_IKI_THRESHOLD_MS: f64 = 200.0;
/// IKI threshold for pause detection (ms)
const PAUSE_IKI_THRESHOLD_MS: f64 = 500.0;

/// Inter-Key Interval distribution (milliseconds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkiDistribution {
    pub mean: f64,
    pub std_dev: f64,
    /// Human typing is typically right-skewed
    pub skewness: f64,
    /// Excess kurtosis (0 = normal)
    pub kurtosis: f64,
    /// [5th, 25th, 50th, 75th, 95th]
    pub percentiles: [f64; 5],
    /// Normalized 50ms-wide histogram buckets
    pub histogram: Vec<f64>,
    /// Pearson autocorrelation of IKI[i] with IKI[i+1]
    #[serde(default)]
    pub autocorrelation_lag1: f64,
    /// Pearson autocorrelation of IKI[i] with IKI[i+2]
    #[serde(default)]
    pub autocorrelation_lag2: f64,
}

impl Default for IkiDistribution {
    fn default() -> Self {
        Self {
            mean: 0.0,
            std_dev: 0.0,
            skewness: 0.0,
            kurtosis: 0.0,
            percentiles: [0.0; 5],
            histogram: vec![0.0; IKI_HISTOGRAM_BUCKETS],
            autocorrelation_lag1: 0.0,
            autocorrelation_lag2: 0.0,
        }
    }
}

impl IkiDistribution {
    /// Build from raw IKI values (ms).
    pub fn from_intervals(intervals: &[f64]) -> Self {
        if intervals.is_empty() {
            return Self::default();
        }

        // M-045: filter NaN/inf before any statistical computation or sort
        let mut intervals = intervals.to_vec();
        intervals.retain(|x| x.is_finite());
        if intervals.is_empty() {
            return Self::default();
        }
        let intervals = intervals.as_slice();

        let (mean, variance) = crate::utils::stats::mean_and_sample_variance(intervals);
        let std_dev = if variance > 0.0 { variance.sqrt() } else { 0.0 };

        let skewness = {
            let s = stats::skewness(intervals, mean, std_dev);
            if s.is_finite() {
                s
            } else {
                log::warn!(
                    "IkiDistribution::from_intervals: skewness is non-finite, substituting 0.0"
                );
                0.0
            }
        };
        let kurtosis = {
            let k = stats::kurtosis(intervals, mean, std_dev);
            if k.is_finite() {
                k
            } else {
                log::warn!(
                    "IkiDistribution::from_intervals: kurtosis is non-finite, substituting 0.0"
                );
                0.0
            }
        };

        // O(n) percentile selection via select_nth_unstable
        let percentiles = {
            let mut buf = intervals.to_vec();
            let n = buf.len();
            let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
            let pcts = [0.05, 0.25, 0.50, 0.75, 0.95];
            let mut vals = [0.0f64; 5];
            for (i, &p) in pcts.iter().enumerate() {
                let idx = (p * (n.saturating_sub(1)) as f64).round() as usize;
                let idx = idx.min(n.saturating_sub(1));
                buf.select_nth_unstable_by(idx, cmp);
                vals[i] = buf[idx];
            }
            vals
        };

        let mut histogram = vec![0.0; IKI_HISTOGRAM_BUCKETS];
        for &iki in intervals {
            let bucket = ((iki / IKI_BUCKET_WIDTH_MS) as usize).min(IKI_HISTOGRAM_BUCKETS - 1);
            histogram[bucket] += 1.0;
        }
        let total: f64 = histogram.iter().sum();
        if total > 0.0 {
            for h in &mut histogram {
                *h /= total;
            }
        }

        let autocorrelation_lag1 = pearson_autocorrelation(intervals, 1);
        let autocorrelation_lag2 = pearson_autocorrelation(intervals, 2);

        Self {
            mean,
            std_dev,
            skewness,
            kurtosis,
            percentiles,
            histogram,
            autocorrelation_lag1,
            autocorrelation_lag2,
        }
    }

    /// Weighted merge with another distribution.
    pub fn merge(&mut self, other: &IkiDistribution, self_weight: f64, other_weight: f64) {
        self.weighted_merge(other, self_weight, other_weight);
    }

    /// Similarity (0.0-1.0) via Bhattacharyya coefficient on histograms.
    pub fn similarity(&self, other: &IkiDistribution) -> f64 {
        <Self as WeightedDistribution>::similarity(self, other)
    }
}

impl WeightedDistribution for IkiDistribution {
    fn similarity(&self, other: &Self) -> f64 {
        let hist_sim =
            crate::analysis::stats::bhattacharyya_coefficient(&self.histogram, &other.histogram);

        let mean_sim = 1.0 - (self.mean - other.mean).abs() / (self.mean + other.mean + 1.0);
        let std_sim =
            1.0 - (self.std_dev - other.std_dev).abs() / (self.std_dev + other.std_dev + 1.0);
        let ac_sim = 1.0
            - (self.autocorrelation_lag1 - other.autocorrelation_lag1)
                .abs()
                .min(1.0);

        // H-062: guard against NaN propagation into the weighted sum
        if !hist_sim.is_finite()
            || !mean_sim.is_finite()
            || !std_sim.is_finite()
            || !ac_sim.is_finite()
        {
            return 0.5; // inconclusive
        }

        crate::utils::Probability::clamp(
            hist_sim * 0.50 + mean_sim * 0.20 + std_sim * 0.20 + ac_sim * 0.10,
        )
        .get()
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        self.mean = weighted_blend(self.mean, other.mean, self_weight, other_weight);
        self.std_dev = weighted_blend(self.std_dev, other.std_dev, self_weight, other_weight);
        self.skewness = weighted_blend(self.skewness, other.skewness, self_weight, other_weight);
        self.kurtosis = weighted_blend(self.kurtosis, other.kurtosis, self_weight, other_weight);
        self.autocorrelation_lag1 = weighted_blend(
            self.autocorrelation_lag1,
            other.autocorrelation_lag1,
            self_weight,
            other_weight,
        );
        self.autocorrelation_lag2 = weighted_blend(
            self.autocorrelation_lag2,
            other.autocorrelation_lag2,
            self_weight,
            other_weight,
        );

        for i in 0..5 {
            self.percentiles[i] = weighted_blend(
                self.percentiles[i],
                other.percentiles[i],
                self_weight,
                other_weight,
            );
        }

        merge_histogram(
            &mut self.histogram,
            &other.histogram,
            self_weight,
            other_weight,
        );
    }
}

/// Keyboard zone usage profile.
///
/// Zones 0-3: left hand (pinky to index), 4-7: right hand (index to pinky).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneProfile {
    pub zone_frequencies: [f64; 8],
    pub zone_transitions: Vec<f64>,
    pub same_finger_histogram: Vec<f64>,
    pub same_hand_histogram: Vec<f64>,
    pub alternating_histogram: Vec<f64>,
    /// Average dwell time (ms) per zone
    #[serde(default)]
    pub zone_dwell_means: [f64; 8],
}

impl Default for ZoneProfile {
    fn default() -> Self {
        Self {
            zone_frequencies: [0.125; 8],
            zone_transitions: vec![0.0; ZONE_TRANSITIONS],
            same_finger_histogram: vec![0.0; 20],
            same_hand_histogram: vec![0.0; 20],
            alternating_histogram: vec![0.0; 20],
            zone_dwell_means: [0.0; 8],
        }
    }
}

impl ZoneProfile {
    /// Build zone profile from jitter samples.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        let mut profile = Self::default();

        if samples.is_empty() {
            return profile;
        }

        // Single pass: accumulate zone counts, transitions, IKI histograms, and dwell
        let mut zone_counts = [0usize; 8];
        let mut transitions = vec![0usize; ZONE_TRANSITIONS];
        let mut zone_dwell_sums = [0.0f64; 8];
        let mut zone_dwell_counts = [0usize; 8];

        let z0_idx = (samples[0].zone as usize).min(7);
        zone_counts[z0_idx] += 1;
        if let Some(dwell_ns) = samples[0].dwell_time_ns {
            if dwell_ns > 0 {
                let dwell_ms = dwell_ns as f64 / 1_000_000.0;
                if dwell_ms.is_finite() {
                    zone_dwell_sums[z0_idx] += dwell_ms;
                    zone_dwell_counts[z0_idx] += 1;
                }
            }
        }
        for w in samples.windows(2) {
            let z0 = (w[0].zone as usize).min(7);
            let z1 = (w[1].zone as usize).min(7);
            zone_counts[z1] += 1;
            transitions[z0 * 8 + z1] += 1;

            if let Some(dwell_ns) = w[1].dwell_time_ns {
                if dwell_ns > 0 {
                    let dwell_ms = dwell_ns as f64 / 1_000_000.0;
                    if dwell_ms.is_finite() {
                        zone_dwell_sums[z1] += dwell_ms;
                        zone_dwell_counts[z1] += 1;
                    }
                }
            }

            let iki_ms = match w[1].timestamp_ns.checked_sub(w[0].timestamp_ns) {
                Some(d) if d > 0 => crate::utils::ns_to_ms(d),
                _ => continue,
            };
            let bucket = ((iki_ms / 50.0) as usize).min(19);
            if z0 == z1 {
                profile.same_finger_histogram[bucket] += 1.0;
            } else if (z0 < 4) == (z1 < 4) {
                profile.same_hand_histogram[bucket] += 1.0;
            } else {
                profile.alternating_histogram[bucket] += 1.0;
            }
        }

        let total: usize = zone_counts.iter().sum();
        if total > 0 {
            for (i, &count) in zone_counts.iter().enumerate() {
                profile.zone_frequencies[i] = count as f64 / total as f64;
            }
        }
        let trans_total: usize = transitions.iter().sum();
        if trans_total > 0 {
            for (i, &count) in transitions.iter().enumerate() {
                profile.zone_transitions[i] = count as f64 / trans_total as f64;
            }
        }

        normalize_histogram(&mut profile.same_finger_histogram);
        normalize_histogram(&mut profile.same_hand_histogram);
        normalize_histogram(&mut profile.alternating_histogram);

        for i in 0..8 {
            if zone_dwell_counts[i] > 0 {
                profile.zone_dwell_means[i] =
                    zone_dwell_sums[i] / zone_dwell_counts[i] as f64;
            }
        }

        profile
    }

    /// Weighted merge with another profile.
    pub fn merge(&mut self, other: &ZoneProfile, self_weight: f64, other_weight: f64) {
        self.weighted_merge(other, self_weight, other_weight);
    }

    /// Similarity (0.0-1.0) based on zone frequencies and transitions.
    pub fn similarity(&self, other: &ZoneProfile) -> f64 {
        <Self as WeightedDistribution>::similarity(self, other)
    }

    /// Return the most frequently used zone as a human-readable string.
    pub fn dominant_zone(&self) -> String {
        let (zone_idx, freq) = self
            .zone_frequencies
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, &0.0));

        let zone_names = [
            "Left Pinky",
            "Left Ring",
            "Left Middle",
            "Left Index",
            "Right Index",
            "Right Middle",
            "Right Ring",
            "Right Pinky",
        ];
        format!("{} ({:.0}%)", zone_names[zone_idx], freq * 100.0)
    }
}

impl WeightedDistribution for ZoneProfile {
    fn similarity(&self, other: &Self) -> f64 {
        let freq_sim: f64 = self
            .zone_frequencies
            .iter()
            .zip(other.zone_frequencies.iter())
            .map(|(a, b)| 1.0 - (a - b).abs())
            .sum::<f64>()
            / 8.0;

        let trans_sim: f64 = self
            .zone_transitions
            .iter()
            .zip(other.zone_transitions.iter())
            .map(|(a, b)| a.min(*b))
            .sum();

        // Cosine similarity on per-zone dwell means
        let dwell_sim = {
            let mut dot = 0.0f64;
            let mut mag_a = 0.0f64;
            let mut mag_b = 0.0f64;
            for i in 0..8 {
                dot += self.zone_dwell_means[i] * other.zone_dwell_means[i];
                mag_a += self.zone_dwell_means[i] * self.zone_dwell_means[i];
                mag_b += other.zone_dwell_means[i] * other.zone_dwell_means[i];
            }
            let denom = mag_a.sqrt() * mag_b.sqrt();
            if denom > 0.0 {
                let cos = dot / denom;
                if cos.is_finite() { cos.clamp(0.0, 1.0) } else { 0.5 }
            } else {
                0.5
            }
        };

        crate::utils::Probability::clamp(
            freq_sim * 0.30 + trans_sim * 0.40 + dwell_sim * 0.30,
        )
        .get()
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        for i in 0..8 {
            self.zone_frequencies[i] = weighted_blend(
                self.zone_frequencies[i],
                other.zone_frequencies[i],
                self_weight,
                other_weight,
            );
            self.zone_dwell_means[i] = weighted_blend(
                self.zone_dwell_means[i],
                other.zone_dwell_means[i],
                self_weight,
                other_weight,
            );
        }

        merge_histogram(
            &mut self.zone_transitions,
            &other.zone_transitions,
            self_weight,
            other_weight,
        );
        merge_histogram(
            &mut self.same_finger_histogram,
            &other.same_finger_histogram,
            self_weight,
            other_weight,
        );
        merge_histogram(
            &mut self.same_hand_histogram,
            &other.same_hand_histogram,
            self_weight,
            other_weight,
        );
        merge_histogram(
            &mut self.alternating_histogram,
            &other.alternating_histogram,
            self_weight,
            other_weight,
        );
    }
}

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

        let mut sentence_pauses = Vec::new();
        let mut paragraph_pauses = Vec::new();
        let mut thinking_pauses = Vec::new();

        for &iki in intervals {
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
        for &iki in intervals {
            if iki >= SENTENCE_PAUSE_MS {
                let bucket = ((iki / PAUSE_BUCKET_WIDTH_MS) as usize)
                    .min(PAUSE_HISTOGRAM_BUCKETS - 1);
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

/// Typing activity distribution by hour of day (0-23).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircadianPattern {
    pub hourly_activity: [f64; 24],
    pub total_samples: u64,
}

impl Default for CircadianPattern {
    fn default() -> Self {
        Self {
            hourly_activity: [0.0; 24],
            total_samples: 0,
        }
    }
}

impl CircadianPattern {
    /// Record a keystroke at the given hour (0-23).
    pub fn record(&mut self, hour: u8) {
        if hour < 24 {
            self.hourly_activity[hour as usize] += 1.0;
            self.total_samples += 1;
        }
    }

    /// Normalize to sum to 1.0.
    pub fn normalize(&mut self) {
        let total: f64 = self.hourly_activity.iter().sum();
        if total > 0.0 {
            for h in &mut self.hourly_activity {
                *h /= total;
            }
        }
    }

    /// Additive merge (re-normalize after merging).
    pub fn merge(&mut self, other: &CircadianPattern) {
        for i in 0..24 {
            self.hourly_activity[i] += other.hourly_activity[i];
        }
        self.total_samples += other.total_samples;
    }
}

/// Session-level typing characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSignature {
    pub mean_session_duration: f64,
    /// Keystrokes per minute
    pub mean_typing_speed: f64,
    /// Speed decay over session duration
    pub fatigue_coefficient: f64,
    pub session_count: u32,
    /// Fraction of time spent in bursts (<200ms IKI) vs pauses (>500ms)
    #[serde(default)]
    pub burst_pause_ratio: f64,
    /// Average number of consecutive keystrokes with IKI < 200ms
    #[serde(default)]
    pub mean_burst_length: f64,
}

impl Default for SessionSignature {
    fn default() -> Self {
        Self {
            mean_session_duration: 0.0,
            mean_typing_speed: 0.0,
            fatigue_coefficient: 0.0,
            session_count: 0,
            burst_pause_ratio: 0.0,
            mean_burst_length: 0.0,
        }
    }
}

impl SessionSignature {
    /// Compute burst/pause metrics from IKI intervals.
    pub fn compute_burst_metrics(&mut self, intervals: &[f64]) {
        if intervals.is_empty() {
            return;
        }
        let mut burst_count = 0.0f64;
        let mut pause_count = 0.0f64;
        let mut burst_lengths = Vec::new();
        let mut current_burst = 0usize;

        for &iki in intervals {
            if !iki.is_finite() {
                continue;
            }
            if iki < BURST_IKI_THRESHOLD_MS {
                burst_count += 1.0;
                current_burst += 1;
            } else {
                if current_burst > 0 {
                    burst_lengths.push(current_burst as f64);
                    current_burst = 0;
                }
                if iki > PAUSE_IKI_THRESHOLD_MS {
                    pause_count += 1.0;
                }
            }
        }
        if current_burst > 0 {
            burst_lengths.push(current_burst as f64);
        }

        let total = burst_count + pause_count;
        self.burst_pause_ratio = if total > 0.0 {
            burst_count / total
        } else {
            0.0
        };
        self.mean_burst_length = if !burst_lengths.is_empty() {
            burst_lengths.iter().sum::<f64>() / burst_lengths.len() as f64
        } else {
            0.0
        };
    }

    /// Weighted merge by session count.
    pub fn merge(&mut self, other: &SessionSignature) {
        let total = self.session_count + other.session_count;
        if total == 0 {
            return;
        }
        let self_w = self.session_count as f64 / total as f64;
        let other_w = other.session_count as f64 / total as f64;

        self.mean_session_duration =
            self.mean_session_duration * self_w + other.mean_session_duration * other_w;
        self.mean_typing_speed =
            self.mean_typing_speed * self_w + other.mean_typing_speed * other_w;
        self.fatigue_coefficient =
            self.fatigue_coefficient * self_w + other.fatigue_coefficient * other_w;
        self.burst_pause_ratio =
            self.burst_pause_ratio * self_w + other.burst_pause_ratio * other_w;
        self.mean_burst_length =
            self.mean_burst_length * self_w + other.mean_burst_length * other_w;
        self.session_count = total;
    }
}

// ---------------------------------------------------------------------------
// Dwell Time Distribution
// ---------------------------------------------------------------------------

/// 10ms buckets covering 0-200ms
const DWELL_HISTOGRAM_BUCKETS: usize = 20;
const DWELL_BUCKET_WIDTH_MS: f64 = 10.0;

/// Key hold duration (keyDown to keyUp) distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwellDistribution {
    pub mean: f64,
    pub std_dev: f64,
    /// [5th, 25th, 50th, 75th, 95th]
    pub percentiles: [f64; 5],
    /// Normalized 10ms-wide histogram buckets (0-200ms)
    pub histogram: Vec<f64>,
}

impl Default for DwellDistribution {
    fn default() -> Self {
        Self {
            mean: 0.0,
            std_dev: 0.0,
            percentiles: [0.0; 5],
            histogram: vec![0.0; DWELL_HISTOGRAM_BUCKETS],
        }
    }
}

impl DwellDistribution {
    /// Build from jitter samples, extracting `dwell_time_ns` values.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        let durations_ms: Vec<f64> = samples
            .iter()
            .filter_map(|s| s.dwell_time_ns)
            .filter(|&ns| ns > 0)
            .map(|ns| ns as f64 / 1_000_000.0)
            .filter(|v| v.is_finite())
            .collect();

        if durations_ms.is_empty() {
            return Self::default();
        }

        let (mean, variance) = crate::utils::stats::mean_and_sample_variance(&durations_ms);
        let std_dev = if variance > 0.0 { variance.sqrt() } else { 0.0 };
        let percentiles = compute_percentiles(&durations_ms);

        let mut histogram = vec![0.0; DWELL_HISTOGRAM_BUCKETS];
        for &v in &durations_ms {
            let bucket = ((v / DWELL_BUCKET_WIDTH_MS) as usize).min(DWELL_HISTOGRAM_BUCKETS - 1);
            histogram[bucket] += 1.0;
        }
        normalize_histogram(&mut histogram);

        Self {
            mean,
            std_dev,
            percentiles,
            histogram,
        }
    }
}

impl WeightedDistribution for DwellDistribution {
    fn similarity(&self, other: &Self) -> f64 {
        let hist_sim = stats::bhattacharyya_coefficient(&self.histogram, &other.histogram);
        let mean_sim = 1.0 - (self.mean - other.mean).abs() / (self.mean + other.mean + 1.0);
        let std_sim =
            1.0 - (self.std_dev - other.std_dev).abs() / (self.std_dev + other.std_dev + 1.0);

        if !hist_sim.is_finite() || !mean_sim.is_finite() || !std_sim.is_finite() {
            return 0.5;
        }

        crate::utils::Probability::clamp(hist_sim * 0.6 + mean_sim * 0.2 + std_sim * 0.2).get()
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        self.mean = weighted_blend(self.mean, other.mean, self_weight, other_weight);
        self.std_dev = weighted_blend(self.std_dev, other.std_dev, self_weight, other_weight);
        for i in 0..5 {
            self.percentiles[i] = weighted_blend(
                self.percentiles[i],
                other.percentiles[i],
                self_weight,
                other_weight,
            );
        }
        merge_histogram(
            &mut self.histogram,
            &other.histogram,
            self_weight,
            other_weight,
        );
    }
}

// ---------------------------------------------------------------------------
// Flight Time Distribution
// ---------------------------------------------------------------------------

/// 25ms buckets covering 0-500ms
const FLIGHT_HISTOGRAM_BUCKETS: usize = 20;
const FLIGHT_BUCKET_WIDTH_MS: f64 = 25.0;

/// Key-release to next key-press interval distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightTimeDistribution {
    pub mean: f64,
    pub std_dev: f64,
    /// [5th, 25th, 50th, 75th, 95th]
    pub percentiles: [f64; 5],
    /// Normalized 25ms-wide histogram buckets (0-500ms)
    pub histogram: Vec<f64>,
}

impl Default for FlightTimeDistribution {
    fn default() -> Self {
        Self {
            mean: 0.0,
            std_dev: 0.0,
            percentiles: [0.0; 5],
            histogram: vec![0.0; FLIGHT_HISTOGRAM_BUCKETS],
        }
    }
}

impl FlightTimeDistribution {
    /// Build from jitter samples, extracting `flight_time_ns` values.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        let durations_ms: Vec<f64> = samples
            .iter()
            .filter_map(|s| s.flight_time_ns)
            .filter(|&ns| ns > 0)
            .map(|ns| ns as f64 / 1_000_000.0)
            .filter(|v| v.is_finite())
            .collect();

        if durations_ms.is_empty() {
            return Self::default();
        }

        let (mean, variance) = crate::utils::stats::mean_and_sample_variance(&durations_ms);
        let std_dev = if variance > 0.0 { variance.sqrt() } else { 0.0 };
        let percentiles = compute_percentiles(&durations_ms);

        let mut histogram = vec![0.0; FLIGHT_HISTOGRAM_BUCKETS];
        for &v in &durations_ms {
            let bucket =
                ((v / FLIGHT_BUCKET_WIDTH_MS) as usize).min(FLIGHT_HISTOGRAM_BUCKETS - 1);
            histogram[bucket] += 1.0;
        }
        normalize_histogram(&mut histogram);

        Self {
            mean,
            std_dev,
            percentiles,
            histogram,
        }
    }
}

impl WeightedDistribution for FlightTimeDistribution {
    fn similarity(&self, other: &Self) -> f64 {
        let hist_sim = stats::bhattacharyya_coefficient(&self.histogram, &other.histogram);
        let mean_sim = 1.0 - (self.mean - other.mean).abs() / (self.mean + other.mean + 1.0);
        let std_sim =
            1.0 - (self.std_dev - other.std_dev).abs() / (self.std_dev + other.std_dev + 1.0);

        if !hist_sim.is_finite() || !mean_sim.is_finite() || !std_sim.is_finite() {
            return 0.5;
        }

        crate::utils::Probability::clamp(hist_sim * 0.6 + mean_sim * 0.2 + std_sim * 0.2).get()
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        self.mean = weighted_blend(self.mean, other.mean, self_weight, other_weight);
        self.std_dev = weighted_blend(self.std_dev, other.std_dev, self_weight, other_weight);
        for i in 0..5 {
            self.percentiles[i] = weighted_blend(
                self.percentiles[i],
                other.percentiles[i],
                self_weight,
                other_weight,
            );
        }
        merge_histogram(
            &mut self.histogram,
            &other.histogram,
            self_weight,
            other_weight,
        );
    }
}

// ---------------------------------------------------------------------------
// Digraph Profile (zone-pair IKI timing)
// ---------------------------------------------------------------------------

/// Per-digraph (zone pair) timing statistics computed via Welford's algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigraphTiming {
    pub count: u64,
    pub mean_ms: f64,
    pub std_dev_ms: f64,
}

impl Default for DigraphTiming {
    fn default() -> Self {
        Self {
            count: 0,
            mean_ms: 0.0,
            std_dev_ms: 0.0,
        }
    }
}

/// Top-N digraph (consecutive zone pair) IKI timing profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigraphProfile {
    pub digraph_timings: HashMap<(u8, u8), DigraphTiming>,
}

impl Default for DigraphProfile {
    fn default() -> Self {
        Self {
            digraph_timings: HashMap::new(),
        }
    }
}

impl DigraphProfile {
    /// Build digraph profile from consecutive sample pairs using Welford's
    /// online algorithm for per-digraph mean and variance.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        if samples.len() < 2 {
            return Self::default();
        }

        // Welford accumulators: (count, mean, M2)
        let mut accumulators: HashMap<(u8, u8), (u64, f64, f64)> = HashMap::new();

        for w in samples.windows(2) {
            let iki_ns = match w[1].timestamp_ns.checked_sub(w[0].timestamp_ns) {
                Some(d) if d > 0 => d,
                _ => continue,
            };
            let iki_ms = iki_ns as f64 / 1_000_000.0;
            if !iki_ms.is_finite() || iki_ms >= 10000.0 {
                continue;
            }

            let key = (w[0].zone.min(7), w[1].zone.min(7));
            let entry = accumulators.entry(key).or_insert((0, 0.0, 0.0));
            entry.0 += 1;
            let delta = iki_ms - entry.1;
            entry.1 += delta / entry.0 as f64;
            let delta2 = iki_ms - entry.1;
            entry.2 += delta * delta2;
        }

        let digraph_timings = accumulators
            .into_iter()
            .map(|(key, (count, mean, m2))| {
                let std_dev = if count > 1 {
                    (m2 / (count - 1) as f64).sqrt()
                } else {
                    0.0
                };
                (
                    key,
                    DigraphTiming {
                        count,
                        mean_ms: mean,
                        std_dev_ms: if std_dev.is_finite() { std_dev } else { 0.0 },
                    },
                )
            })
            .collect();

        Self { digraph_timings }
    }

    /// Weighted cosine similarity of mean_ms vectors over shared digraph keys.
    /// Returns 0.5 if fewer than 10 shared digraphs (inconclusive).
    pub fn similarity(&self, other: &Self) -> f64 {
        <Self as WeightedDistribution>::similarity(self, other)
    }
}

impl WeightedDistribution for DigraphProfile {
    fn similarity(&self, other: &Self) -> f64 {
        let mut dot = 0.0f64;
        let mut norm_a = 0.0f64;
        let mut norm_b = 0.0f64;
        let mut shared = 0usize;

        for (key, timing_a) in &self.digraph_timings {
            if let Some(timing_b) = other.digraph_timings.get(key) {
                let w = (timing_a.count.min(timing_b.count)) as f64;
                let va = timing_a.mean_ms * w;
                let vb = timing_b.mean_ms * w;
                dot += va * vb;
                norm_a += va * va;
                norm_b += vb * vb;
                shared += 1;
            }
        }

        if shared < 10 {
            return 0.5;
        }

        if norm_a <= 0.0 || norm_b <= 0.0 {
            return 0.5;
        }

        let cosine = dot / (norm_a.sqrt() * norm_b.sqrt());
        if !cosine.is_finite() {
            return 0.5;
        }

        crate::utils::Probability::clamp(cosine).get()
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        for (key, other_timing) in &other.digraph_timings {
            let entry = self
                .digraph_timings
                .entry(*key)
                .or_insert_with(DigraphTiming::default);
            let weighted_self = entry.count as f64 * self_weight;
            let weighted_other = other_timing.count as f64 * other_weight;
            let total = weighted_self + weighted_other;
            if total > 0.0 {
                let sw = weighted_self / total;
                let ow = weighted_other / total;
                entry.mean_ms = weighted_blend(entry.mean_ms, other_timing.mean_ms, sw, ow);
                entry.std_dev_ms =
                    weighted_blend(entry.std_dev_ms, other_timing.std_dev_ms, sw, ow);
            }
            entry.count = total.round() as u64;
        }
        // Scale counts for keys only in self
        for (key, timing) in &mut self.digraph_timings {
            if !other.digraph_timings.contains_key(key) {
                timing.count = (timing.count as f64 * self_weight).round() as u64;
            }
        }
        // Remove entries that rounded to zero
        self.digraph_timings.retain(|_, t| t.count > 0);
    }
}

// ---------------------------------------------------------------------------
// Per-Dimension Confidence
// ---------------------------------------------------------------------------

/// Per-dimension confidence scores, each saturating at a feature-specific
/// sample count that reflects how many samples are needed for stability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionConfidence {
    pub iki: f64,
    pub zone: f64,
    pub pause: f64,
    pub dwell: f64,
    pub flight: f64,
    pub digraph: f64,
    pub hurst: f64,
    pub circadian: f64,
}

impl Default for DimensionConfidence {
    fn default() -> Self {
        Self {
            iki: 0.0,
            zone: 0.0,
            pause: 0.0,
            dwell: 0.0,
            flight: 0.0,
            digraph: 0.0,
            hurst: 0.0,
            circadian: 0.0,
        }
    }
}

impl DimensionConfidence {
    const IKI_SAT: f64 = 200.0;
    const ZONE_SAT: f64 = 300.0;
    const PAUSE_SAT: f64 = 500.0;
    const DWELL_SAT: f64 = 200.0;
    const FLIGHT_SAT: f64 = 200.0;
    const DIGRAPH_SAT: f64 = 1000.0;
    const HURST_SAT: f64 = 500.0;
    const CIRCADIAN_SAT: f64 = 5000.0;

    /// Compute per-dimension confidence from sample count and data availability.
    pub fn from_sample_count(
        sample_count: u64,
        has_dwell: bool,
        has_flight: bool,
        has_hurst: bool,
        circadian_samples: u64,
    ) -> Self {
        let n = sample_count as f64;
        Self {
            iki: (n / Self::IKI_SAT).min(1.0),
            zone: (n / Self::ZONE_SAT).min(1.0),
            pause: (n / Self::PAUSE_SAT).min(1.0),
            dwell: if has_dwell {
                (n / Self::DWELL_SAT).min(1.0)
            } else {
                0.0
            },
            flight: if has_flight {
                (n / Self::FLIGHT_SAT).min(1.0)
            } else {
                0.0
            },
            digraph: (n / Self::DIGRAPH_SAT).min(1.0),
            hurst: if has_hurst {
                (n / Self::HURST_SAT).min(1.0)
            } else {
                0.0
            },
            circadian: (circadian_samples as f64 / Self::CIRCADIAN_SAT).min(1.0),
        }
    }

    /// Weighted average across all dimensions (circadian at half weight).
    pub fn overall(&self) -> f64 {
        let weights = [0.25, 0.15, 0.10, 0.10, 0.10, 0.15, 0.05, 0.05];
        let values = [
            self.iki,
            self.zone,
            self.pause,
            self.dwell,
            self.flight,
            self.digraph,
            self.hurst,
            self.circadian,
        ];
        values
            .iter()
            .zip(weights.iter())
            .map(|(v, w)| v * w)
            .sum::<f64>()
            / weights.iter().sum::<f64>()
    }
}

// ---------------------------------------------------------------------------
// Shared percentile helper
// ---------------------------------------------------------------------------

/// Pearson autocorrelation of a time series at the given lag.
/// Returns 0.0 if the series is too short or has zero variance.
fn pearson_autocorrelation(series: &[f64], lag: usize) -> f64 {
    if series.len() <= lag {
        return 0.0;
    }
    let n = series.len() - lag;
    let mean_x: f64 = series[..n].iter().sum::<f64>() / n as f64;
    let mean_y: f64 = series[lag..].iter().sum::<f64>() / n as f64;

    let mut cov = 0.0f64;
    let mut var_x = 0.0f64;
    let mut var_y = 0.0f64;
    for i in 0..n {
        let dx = series[i] - mean_x;
        let dy = series[i + lag] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    let denom = (var_x * var_y).sqrt();
    if denom <= 0.0 || !denom.is_finite() {
        return 0.0;
    }
    let r = cov / denom;
    if r.is_finite() { r.clamp(-1.0, 1.0) } else { 0.0 }
}

/// O(n) percentile selection for [5th, 25th, 50th, 75th, 95th].
fn compute_percentiles(data: &[f64]) -> [f64; 5] {
    let mut buf = data.to_vec();
    let n = buf.len();
    if n == 0 {
        return [0.0; 5];
    }
    let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
    let pcts = [0.05, 0.25, 0.50, 0.75, 0.95];
    let mut vals = [0.0f64; 5];
    for (i, &p) in pcts.iter().enumerate() {
        let idx = (p * (n.saturating_sub(1)) as f64).round() as usize;
        let idx = idx.min(n.saturating_sub(1));
        buf.select_nth_unstable_by(idx, cmp);
        vals[i] = buf[idx];
    }
    vals
}

#[cfg(test)]
mod analysis_tests {
    use super::*;

    fn make_samples_with_dwell(n: usize) -> Vec<SimpleJitterSample> {
        // Zone pattern produces varied digraphs: zone = (i*3 + i*i/7) % 8
        // This generates 10+ unique zone pairs for n >= 20.
        (0..n)
            .map(|i| SimpleJitterSample {
                timestamp_ns: (i as i64) * 200_000_000,
                duration_since_last_ns: if i == 0 { 0 } else { 200_000_000 },
                zone: ((i * 3 + (i * i) / 7) % 8) as u8,
                dwell_time_ns: Some(80_000_000 + (i as u64 % 40) * 1_000_000),
                flight_time_ns: Some(100_000_000 + (i as u64 % 50) * 1_000_000),
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn test_dwell_distribution_from_samples() {
        let samples = make_samples_with_dwell(50);
        let dist = DwellDistribution::from_samples(&samples);
        assert!(dist.mean > 0.0, "dwell mean should be positive");
        assert!(dist.std_dev > 0.0, "dwell std_dev should be positive");
        assert_eq!(dist.histogram.len(), DWELL_HISTOGRAM_BUCKETS);
        let total: f64 = dist.histogram.iter().sum();
        assert!((total - 1.0).abs() < 1e-9, "histogram should be normalized");
    }

    #[test]
    fn test_dwell_distribution_empty() {
        let dist = DwellDistribution::from_samples(&[]);
        assert_eq!(dist.mean, 0.0);
    }

    #[test]
    fn test_dwell_distribution_no_dwell_data() {
        let samples: Vec<SimpleJitterSample> = (0..10)
            .map(|i| SimpleJitterSample {
                timestamp_ns: (i as i64) * 200_000_000,
                zone: 0,
                dwell_time_ns: None,
                ..Default::default()
            })
            .collect();
        let dist = DwellDistribution::from_samples(&samples);
        assert_eq!(dist.mean, 0.0);
    }

    #[test]
    fn test_dwell_similarity_self() {
        let samples = make_samples_with_dwell(50);
        let dist = DwellDistribution::from_samples(&samples);
        let sim = WeightedDistribution::similarity(&dist, &dist);
        assert!(sim > 0.95, "self-similarity should be near 1.0, got {}", sim);
    }

    #[test]
    fn test_dwell_merge() {
        let samples = make_samples_with_dwell(50);
        let mut d1 = DwellDistribution::from_samples(&samples[..25]);
        let d2 = DwellDistribution::from_samples(&samples[25..]);
        d1.weighted_merge(&d2, 0.5, 0.5);
        assert!(d1.mean > 0.0);
    }

    #[test]
    fn test_flight_distribution_from_samples() {
        let samples = make_samples_with_dwell(50);
        let dist = FlightTimeDistribution::from_samples(&samples);
        assert!(dist.mean > 0.0, "flight mean should be positive");
        assert_eq!(dist.histogram.len(), FLIGHT_HISTOGRAM_BUCKETS);
    }

    #[test]
    fn test_flight_distribution_empty() {
        let dist = FlightTimeDistribution::from_samples(&[]);
        assert_eq!(dist.mean, 0.0);
    }

    #[test]
    fn test_flight_similarity_self() {
        let samples = make_samples_with_dwell(50);
        let dist = FlightTimeDistribution::from_samples(&samples);
        let sim = WeightedDistribution::similarity(&dist, &dist);
        assert!(sim > 0.95, "self-similarity should be near 1.0, got {}", sim);
    }

    #[test]
    fn test_flight_merge() {
        let samples = make_samples_with_dwell(50);
        let mut f1 = FlightTimeDistribution::from_samples(&samples[..25]);
        let f2 = FlightTimeDistribution::from_samples(&samples[25..]);
        f1.weighted_merge(&f2, 0.5, 0.5);
        assert!(f1.mean > 0.0);
    }

    #[test]
    fn test_digraph_profile_from_samples() {
        let samples = make_samples_with_dwell(100);
        let profile = DigraphProfile::from_samples(&samples);
        assert!(
            !profile.digraph_timings.is_empty(),
            "digraph timings should not be empty"
        );
        for timing in profile.digraph_timings.values() {
            assert!(timing.count > 0);
            assert!(timing.mean_ms > 0.0);
        }
    }

    #[test]
    fn test_digraph_profile_empty() {
        let profile = DigraphProfile::from_samples(&[]);
        assert!(profile.digraph_timings.is_empty());
    }

    #[test]
    fn test_digraph_similarity_self() {
        let samples = make_samples_with_dwell(100);
        let profile = DigraphProfile::from_samples(&samples);
        let sim = WeightedDistribution::similarity(&profile, &profile);
        assert!(sim > 0.95, "self-similarity should be near 1.0, got {}", sim);
    }

    #[test]
    fn test_digraph_similarity_few_shared() {
        let s1: Vec<SimpleJitterSample> = (0..5)
            .map(|i| SimpleJitterSample {
                timestamp_ns: (i as i64) * 200_000_000,
                zone: 0,
                ..Default::default()
            })
            .collect();
        let s2: Vec<SimpleJitterSample> = (0..5)
            .map(|i| SimpleJitterSample {
                timestamp_ns: (i as i64) * 200_000_000,
                zone: 7,
                ..Default::default()
            })
            .collect();
        let p1 = DigraphProfile::from_samples(&s1);
        let p2 = DigraphProfile::from_samples(&s2);
        let sim = WeightedDistribution::similarity(&p1, &p2);
        assert!(
            (sim - 0.5).abs() < 1e-9,
            "few shared digraphs should return 0.5, got {}",
            sim
        );
    }

    #[test]
    fn test_digraph_merge() {
        let samples = make_samples_with_dwell(100);
        let mut p1 = DigraphProfile::from_samples(&samples[..50]);
        let p2 = DigraphProfile::from_samples(&samples[50..]);
        p1.weighted_merge(&p2, 0.5, 0.5);
        assert!(!p1.digraph_timings.is_empty());
    }

    #[test]
    fn test_dimension_confidence_saturation() {
        let dc = DimensionConfidence::from_sample_count(1000, true, true, true, 5000);
        assert!((dc.iki - 1.0).abs() < 1e-9, "iki should saturate at 200");
        assert!(
            (dc.circadian - 1.0).abs() < 1e-9,
            "circadian should saturate at 5000"
        );
        assert!(dc.overall() > 0.0);
    }

    #[test]
    fn test_dimension_confidence_partial() {
        let dc = DimensionConfidence::from_sample_count(100, false, false, false, 0);
        assert_eq!(dc.dwell, 0.0, "no dwell data should yield 0");
        assert_eq!(dc.flight, 0.0, "no flight data should yield 0");
        assert_eq!(dc.hurst, 0.0, "no hurst data should yield 0");
        assert!(dc.iki > 0.0);
    }

    #[test]
    fn test_iki_autocorrelation() {
        // Strongly correlated series: each IKI = previous + small delta
        let intervals: Vec<f64> = (0..50).map(|i| 100.0 + (i as f64) * 2.0).collect();
        let dist = IkiDistribution::from_intervals(&intervals);
        assert!(
            dist.autocorrelation_lag1 > 0.5,
            "monotonic series should have high lag-1 autocorrelation, got {}",
            dist.autocorrelation_lag1
        );
        assert!(
            dist.autocorrelation_lag2 > 0.3,
            "monotonic series should have positive lag-2 autocorrelation, got {}",
            dist.autocorrelation_lag2
        );
    }

    #[test]
    fn test_iki_autocorrelation_short_series() {
        let dist = IkiDistribution::from_intervals(&[100.0, 200.0]);
        assert_eq!(dist.autocorrelation_lag2, 0.0);
    }

    #[test]
    fn test_iki_autocorrelation_in_similarity() {
        let intervals_a: Vec<f64> = (0..50).map(|i| 100.0 + (i as f64) * 2.0).collect();
        let intervals_b: Vec<f64> = (0..50).map(|i| 100.0 + (i as f64) * 2.0).collect();
        let dist_a = IkiDistribution::from_intervals(&intervals_a);
        let dist_b = IkiDistribution::from_intervals(&intervals_b);
        let sim = WeightedDistribution::similarity(&dist_a, &dist_b);
        assert!(sim > 0.95, "identical series should have high similarity, got {}", sim);
    }

    #[test]
    fn test_zone_dwell_means() {
        let samples = make_samples_with_dwell(50);
        let profile = ZoneProfile::from_samples(&samples);
        let has_nonzero = profile.zone_dwell_means.iter().any(|&v| v > 0.0);
        assert!(has_nonzero, "should have non-zero per-zone dwell means");
    }

    #[test]
    fn test_zone_dwell_means_no_dwell() {
        let samples: Vec<SimpleJitterSample> = (0..10)
            .map(|i| SimpleJitterSample {
                timestamp_ns: (i as i64) * 200_000_000,
                zone: (i % 8) as u8,
                dwell_time_ns: None,
                ..Default::default()
            })
            .collect();
        let profile = ZoneProfile::from_samples(&samples);
        assert!(
            profile.zone_dwell_means.iter().all(|&v| v == 0.0),
            "no dwell data should yield all-zero zone_dwell_means"
        );
    }

    #[test]
    fn test_zone_dwell_in_similarity() {
        let samples = make_samples_with_dwell(50);
        let profile = ZoneProfile::from_samples(&samples);
        let sim = WeightedDistribution::similarity(&profile, &profile);
        assert!(sim > 0.90, "self-similarity should be high, got {}", sim);
    }

    #[test]
    fn test_pause_histogram() {
        let intervals: Vec<f64> = (0..100)
            .map(|i| if i % 10 == 0 { 600.0 } else { 150.0 })
            .collect();
        let sig = PauseSignature::from_intervals(&intervals);
        assert_eq!(sig.pause_histogram.len(), PAUSE_HISTOGRAM_BUCKETS);
        let total: f64 = sig.pause_histogram.iter().sum();
        assert!(
            (total - 1.0).abs() < 1e-9 || total == 0.0,
            "histogram should be normalized or empty"
        );
    }

    #[test]
    fn test_pause_histogram_in_similarity() {
        let intervals: Vec<f64> = (0..100)
            .map(|i| if i % 10 == 0 { 600.0 } else { 150.0 })
            .collect();
        let sig = PauseSignature::from_intervals(&intervals);
        let sim = WeightedDistribution::similarity(&sig, &sig);
        assert!(sim > 0.90, "self-similarity should be high, got {}", sim);
    }

    #[test]
    fn test_session_burst_metrics() {
        // Mix of bursts and pauses
        let intervals = vec![
            100.0, 80.0, 120.0, 90.0, // burst of 4
            600.0, // pause
            110.0, 95.0, // burst of 2
            800.0, // pause
            150.0, // burst of 1
        ];
        let mut sig = SessionSignature::default();
        sig.compute_burst_metrics(&intervals);
        assert!(
            sig.burst_pause_ratio > 0.0 && sig.burst_pause_ratio < 1.0,
            "burst_pause_ratio should be between 0 and 1, got {}",
            sig.burst_pause_ratio
        );
        assert!(
            sig.mean_burst_length > 0.0,
            "mean_burst_length should be positive, got {}",
            sig.mean_burst_length
        );
    }

    #[test]
    fn test_session_burst_metrics_empty() {
        let mut sig = SessionSignature::default();
        sig.compute_burst_metrics(&[]);
        assert_eq!(sig.burst_pause_ratio, 0.0);
        assert_eq!(sig.mean_burst_length, 0.0);
    }

    #[test]
    fn test_dimension_confidence_circadian_downweight() {
        let dc = DimensionConfidence::from_sample_count(1000, true, true, true, 5000);
        // Verify circadian gets 0.05 weight (half of others)
        let weights = [0.25, 0.15, 0.10, 0.10, 0.10, 0.15, 0.05, 0.05];
        let values = [
            dc.iki, dc.zone, dc.pause, dc.dwell, dc.flight, dc.digraph, dc.hurst, dc.circadian,
        ];
        let expected: f64 = values
            .iter()
            .zip(weights.iter())
            .map(|(v, w)| v * w)
            .sum::<f64>()
            / weights.iter().sum::<f64>();
        assert!(
            (dc.overall() - expected).abs() < 1e-9,
            "overall should match expected weighting"
        );
    }

    #[test]
    fn test_pearson_autocorrelation_constant() {
        let series = vec![5.0; 20];
        let r = pearson_autocorrelation(&series, 1);
        assert_eq!(r, 0.0, "constant series should have zero autocorrelation");
    }
}
