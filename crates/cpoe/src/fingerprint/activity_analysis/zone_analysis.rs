// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Keyboard zone usage profile.

use crate::analysis::stats::{merge_histogram, normalize_histogram};
use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

use crate::fingerprint::activity::{weighted_blend, WeightedDistribution};

/// 8x8 zone transition matrix
const ZONE_TRANSITIONS: usize = 64;

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
