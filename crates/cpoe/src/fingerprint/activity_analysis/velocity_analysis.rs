// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Keystroke velocity analysis within typing bursts.
//!
//! Captures typing speed variability (keystrokes/sec) during burst intervals
//! (< 200ms IKI), acceleration between consecutive burst intervals, and
//! maximum sustained speed over rolling 3-keystroke windows.

use serde::{Deserialize, Serialize};

use crate::fingerprint::activity::{weighted_blend, WeightedDistribution};

/// Burst threshold: intervals shorter than this (ms) are considered burst typing.
const BURST_THRESHOLD_MS: f64 = crate::forensics::constants::BURST_THRESHOLD_MS;

/// Rolling window size for max sustained speed.
const ROLLING_WINDOW: usize = 3;

/// Typing velocity profile within bursts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VelocityProfile {
    /// Mean typing speed within bursts (keystrokes/sec).
    pub burst_speed_mean: f64,
    /// Standard deviation of burst typing speed.
    pub burst_speed_std: f64,
    /// Coefficient of variation of burst speed (std / mean).
    pub burst_speed_cv: f64,
    /// Mean acceleration (speed change between consecutive burst intervals).
    pub acceleration_mean: f64,
    /// Maximum sustained speed over a 3-keystroke rolling average (keystrokes/sec).
    pub max_sustained_speed: f64,

    /// Internal: Welford online count for incremental updates.
    #[serde(default)]
    welford_count: u64,
    /// Internal: Welford M2 accumulator.
    #[serde(default)]
    welford_m2: f64,
}

impl VelocityProfile {
    /// Update the velocity profile from raw IKI intervals (milliseconds).
    ///
    /// Filters to burst intervals (< 200ms), computes per-interval speed,
    /// updates statistics using Welford's online algorithm, computes
    /// acceleration, and tracks max 3-keystroke rolling average speed.
    pub fn update(&mut self, intervals_ms: &[f64]) {
        // Filter to burst intervals and convert to speeds (keystrokes/sec).
        let burst_speeds: Vec<f64> = intervals_ms
            .iter()
            .copied()
            .filter(|&i| i.is_finite() && i > 0.0 && i < BURST_THRESHOLD_MS)
            .map(|i| 1000.0 / i)
            .collect();

        if burst_speeds.is_empty() {
            return;
        }

        // Welford's online algorithm for mean and variance.
        for &speed in &burst_speeds {
            self.welford_count += 1;
            let delta = speed - self.burst_speed_mean;
            self.burst_speed_mean += delta / self.welford_count as f64;
            let delta2 = speed - self.burst_speed_mean;
            self.welford_m2 += delta * delta2;
        }

        if self.welford_count >= 2 {
            let variance = self.welford_m2 / (self.welford_count - 1) as f64;
            self.burst_speed_std = if variance > 0.0 { variance.sqrt() } else { 0.0 };
        }

        self.burst_speed_cv = if self.burst_speed_mean > 0.0 {
            self.burst_speed_std / self.burst_speed_mean
        } else {
            0.0
        };

        // Acceleration: difference of consecutive burst speeds.
        if burst_speeds.len() >= 2 {
            let accelerations: Vec<f64> = burst_speeds
                .windows(2)
                .map(|w| w[1] - w[0])
                .collect();
            let acc_sum: f64 = accelerations.iter().sum();
            self.acceleration_mean = acc_sum / accelerations.len() as f64;
            if !self.acceleration_mean.is_finite() {
                self.acceleration_mean = 0.0;
            }
        }

        // Max 3-keystroke rolling average speed.
        if burst_speeds.len() >= ROLLING_WINDOW {
            for window in burst_speeds.windows(ROLLING_WINDOW) {
                let avg = window.iter().sum::<f64>() / ROLLING_WINDOW as f64;
                if avg.is_finite() && avg > self.max_sustained_speed {
                    self.max_sustained_speed = avg;
                }
            }
        } else {
            // Fewer than ROLLING_WINDOW speeds: use the average of what we have.
            let avg = crate::utils::mean(&burst_speeds);
            if avg.is_finite() && avg > self.max_sustained_speed {
                self.max_sustained_speed = avg;
            }
        }
    }
}

impl WeightedDistribution for VelocityProfile {
    fn similarity(&self, other: &Self) -> f64 {
        // Mean speed similarity (normalized difference).
        let mean_sim = 1.0
            - (self.burst_speed_mean - other.burst_speed_mean).abs()
                / (self.burst_speed_mean + other.burst_speed_mean + 1.0);

        // CV similarity (captures variability pattern).
        let cv_sim = 1.0
            - (self.burst_speed_cv - other.burst_speed_cv).abs()
                / (self.burst_speed_cv + other.burst_speed_cv + 0.1);

        // Acceleration similarity.
        let acc_sim = 1.0
            - (self.acceleration_mean - other.acceleration_mean).abs()
                / (self.acceleration_mean.abs() + other.acceleration_mean.abs() + 1.0);

        // Max sustained speed similarity.
        let max_sim = 1.0
            - (self.max_sustained_speed - other.max_sustained_speed).abs()
                / (self.max_sustained_speed + other.max_sustained_speed + 1.0);

        // Guard against NaN propagation.
        if !mean_sim.is_finite()
            || !cv_sim.is_finite()
            || !acc_sim.is_finite()
            || !max_sim.is_finite()
        {
            return 0.5; // inconclusive
        }

        crate::utils::Probability::clamp(
            mean_sim * 0.35 + cv_sim * 0.30 + acc_sim * 0.15 + max_sim * 0.20,
        )
        .get()
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        self.burst_speed_mean = weighted_blend(
            self.burst_speed_mean,
            other.burst_speed_mean,
            self_weight,
            other_weight,
        );
        self.burst_speed_std = weighted_blend(
            self.burst_speed_std,
            other.burst_speed_std,
            self_weight,
            other_weight,
        );
        self.burst_speed_cv = weighted_blend(
            self.burst_speed_cv,
            other.burst_speed_cv,
            self_weight,
            other_weight,
        );
        self.acceleration_mean = weighted_blend(
            self.acceleration_mean,
            other.acceleration_mean,
            self_weight,
            other_weight,
        );
        self.max_sustained_speed = weighted_blend(
            self.max_sustained_speed,
            other.max_sustained_speed,
            self_weight,
            other_weight,
        );

        // Merge Welford state approximately.
        let total = self.welford_count as f64 * self_weight
            + other.welford_count as f64 * other_weight;
        self.welford_count = total.round() as u64;
        self.welford_m2 = weighted_blend(
            self.welford_m2,
            other.welford_m2,
            self_weight,
            other_weight,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_velocity_profile_default() {
        let vp = VelocityProfile::default();
        assert_eq!(vp.burst_speed_mean, 0.0);
        assert_eq!(vp.burst_speed_std, 0.0);
        assert_eq!(vp.burst_speed_cv, 0.0);
        assert_eq!(vp.acceleration_mean, 0.0);
        assert_eq!(vp.max_sustained_speed, 0.0);
    }

    #[test]
    fn test_velocity_profile_update_burst_only() {
        let mut vp = VelocityProfile::default();
        // All intervals < 200ms (burst typing)
        let intervals = vec![80.0, 100.0, 120.0, 90.0, 110.0];
        vp.update(&intervals);

        assert!(vp.burst_speed_mean > 0.0, "mean should be positive");
        assert!(vp.burst_speed_std > 0.0, "std should be positive for varied input");
        assert!(vp.burst_speed_cv > 0.0, "cv should be positive");
        assert!(vp.max_sustained_speed > 0.0, "max sustained should be positive");
    }

    #[test]
    fn test_velocity_profile_filters_non_burst() {
        let mut vp = VelocityProfile::default();
        // Mix of burst and non-burst intervals
        let intervals = vec![80.0, 300.0, 100.0, 500.0, 90.0];
        vp.update(&intervals);

        // Only 3 burst intervals should be processed
        assert_eq!(vp.welford_count, 3);
    }

    #[test]
    fn test_velocity_profile_empty_input() {
        let mut vp = VelocityProfile::default();
        vp.update(&[]);
        assert_eq!(vp.burst_speed_mean, 0.0);
    }

    #[test]
    fn test_velocity_profile_no_burst_intervals() {
        let mut vp = VelocityProfile::default();
        // All intervals >= 200ms
        vp.update(&[300.0, 500.0, 1000.0]);
        assert_eq!(vp.burst_speed_mean, 0.0);
    }

    #[test]
    fn test_velocity_profile_nan_safety() {
        let mut vp = VelocityProfile::default();
        vp.update(&[f64::NAN, 100.0, f64::INFINITY, 80.0]);
        assert!(vp.burst_speed_mean.is_finite());
        assert!(vp.burst_speed_cv.is_finite());
    }

    #[test]
    fn test_velocity_similarity_identical() {
        let mut a = VelocityProfile::default();
        let mut b = VelocityProfile::default();
        let intervals = vec![80.0, 100.0, 120.0, 90.0, 110.0];
        a.update(&intervals);
        b.update(&intervals);

        let sim = a.similarity(&b);
        assert!(sim > 0.95, "identical profiles should be very similar, got {sim}");
    }

    #[test]
    fn test_velocity_similarity_different() {
        let mut a = VelocityProfile::default();
        let mut b = VelocityProfile::default();
        a.update(&[50.0, 60.0, 55.0, 58.0, 52.0]); // fast typist
        b.update(&[180.0, 190.0, 185.0, 195.0, 175.0]); // slow typist

        let sim = a.similarity(&b);
        assert!(sim < 0.7, "different speed profiles should have low similarity, got {sim}");
    }

    #[test]
    fn test_velocity_weighted_merge() {
        let mut a = VelocityProfile::default();
        let mut b = VelocityProfile::default();
        a.update(&[80.0, 100.0, 90.0]);
        b.update(&[120.0, 140.0, 130.0]);

        let a_mean_before = a.burst_speed_mean;
        let b_mean = b.burst_speed_mean;

        a.weighted_merge(&b, 0.5, 0.5);

        // Merged mean should be between the two originals.
        assert!(
            a.burst_speed_mean > b_mean.min(a_mean_before) - 0.1
                && a.burst_speed_mean < b_mean.max(a_mean_before) + 0.1,
            "merged mean {} should be between {} and {}",
            a.burst_speed_mean,
            a_mean_before,
            b_mean
        );
    }

    #[test]
    fn test_velocity_similarity_default_profiles() {
        let a = VelocityProfile::default();
        let b = VelocityProfile::default();
        let sim = a.similarity(&b);
        assert!(sim.is_finite());
        assert!(sim >= 0.0 && sim <= 1.0);
    }
}
