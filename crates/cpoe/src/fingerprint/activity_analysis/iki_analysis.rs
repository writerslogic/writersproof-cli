// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Inter-Key Interval distribution (milliseconds).

use crate::analysis::stats;
use crate::analysis::stats::merge_histogram;
use serde::{Deserialize, Serialize};

use super::distribution_helpers::pearson_autocorrelation;
use crate::fingerprint::activity::{weighted_blend, WeightedDistribution};

/// 50ms buckets covering 0-2500ms
pub(in crate::fingerprint) const IKI_HISTOGRAM_BUCKETS: usize = 50;
const IKI_BUCKET_WIDTH_MS: f64 = 50.0;

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
