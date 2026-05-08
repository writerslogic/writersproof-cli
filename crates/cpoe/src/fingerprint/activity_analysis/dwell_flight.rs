// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Dwell time and flight time distribution types.

use crate::analysis::stats::{self, merge_histogram, normalize_histogram};
use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

use super::distribution_helpers::compute_percentiles;
use crate::fingerprint::activity::{weighted_blend, WeightedDistribution};

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
