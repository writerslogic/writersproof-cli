// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Typing dynamics fingerprint (IKI distribution, zone usage, pause
//! signatures, circadian patterns, session characteristics).
//!
//! Captures *how* you type, not *what* you type. Enabled by default.

use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

// Re-export sub-module types so existing `use activity::*` paths still work.
pub use super::activity_analysis::{
    CircadianPattern, DigraphProfile, DimensionConfidence, DwellDistribution,
    FlightTimeDistribution, IkiDistribution, PauseSignature, SessionSignature, ZoneProfile,
};
pub use super::activity_collection::ActivityFingerprintAccumulator;

/// Shared trait for distribution types that support weighted merging and similarity comparison.
///
/// Implemented by [`IkiDistribution`], [`ZoneProfile`], and [`PauseSignature`], which all
/// share the same merge/similarity interface despite differing internal representations.
pub trait WeightedDistribution {
    /// Similarity score (0.0-1.0) against another distribution of the same type.
    fn similarity(&self, other: &Self) -> f64;

    /// Weighted merge of `other` into `self`.
    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64);
}

/// Linearly blend two scalar values by weight (NaN/Infinity-safe).
#[inline]
pub(super) fn weighted_blend(a: f64, b: f64, a_weight: f64, b_weight: f64) -> f64 {
    crate::utils::stats::weighted_blend(a, b, a_weight, b_weight)
}

/// Typing dynamics fingerprint built from behavioral samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityFingerprint {
    pub id: String,
    pub sample_count: u64,
    /// 0.0-1.0, asymptotic based on sample count
    pub confidence: f64,

    pub iki_distribution: IkiDistribution,
    pub zone_profile: ZoneProfile,
    pub pause_signature: PauseSignature,
    /// Hourly activity distribution
    pub circadian_pattern: CircadianPattern,
    pub session_signature: SessionSignature,

    /// Key hold duration distribution
    #[serde(default)]
    pub dwell_distribution: DwellDistribution,
    /// Key release-to-press interval distribution
    #[serde(default)]
    pub flight_distribution: FlightTimeDistribution,
    /// Per-digraph (zone pair) IKI timing profile
    #[serde(default)]
    pub digraph_profile: DigraphProfile,
    /// Hurst exponent of IKI time series (long-range dependence)
    #[serde(default)]
    pub hurst_exponent: Option<f64>,
    /// Per-dimension confidence scores
    #[serde(default)]
    pub dimension_confidence: DimensionConfidence,

    /// Fraction of samples backed by hardware entropy (0.0-1.0).
    /// Only present when `cpoe_jitter` feature is active.
    #[serde(default)]
    pub phys_ratio: Option<f64>,

    /// Mouse micro-movements while typing (additional biometric signal)
    #[serde(default)]
    pub mouse_idle_stats: Option<crate::platform::MouseIdleStats>,
}

impl Default for ActivityFingerprint {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sample_count: 0,
            confidence: 0.0,
            iki_distribution: IkiDistribution::default(),
            zone_profile: ZoneProfile::default(),
            pause_signature: PauseSignature::default(),
            circadian_pattern: CircadianPattern::default(),
            session_signature: SessionSignature::default(),
            dwell_distribution: DwellDistribution::default(),
            flight_distribution: FlightTimeDistribution::default(),
            digraph_profile: DigraphProfile::default(),
            hurst_exponent: None,
            dimension_confidence: DimensionConfidence::default(),
            phys_ratio: None,
            mouse_idle_stats: None,
        }
    }
}

impl ActivityFingerprint {
    /// Build from raw jitter samples, computing all sub-distributions.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        log::debug!("ActivityFingerprint::from_samples: count={}", samples.len());
        if samples.len() < 2 {
            return Self {
                sample_count: samples.len() as u64,
                ..Self::default()
            };
        }

        let mut fp = Self {
            sample_count: samples.len() as u64,
            ..Self::default()
        };

        let ikis: Vec<f64> = samples
            .windows(2)
            .filter_map(|w| {
                w[1].timestamp_ns
                    .checked_sub(w[0].timestamp_ns)
                    .map(crate::utils::ns_to_ms)
            })
            .filter(|&i| i > 0.0 && i < 10000.0)
            .collect();

        if ikis.is_empty() {
            return fp;
        }

        fp.iki_distribution = IkiDistribution::from_intervals(&ikis);
        fp.zone_profile = ZoneProfile::from_samples(samples);
        fp.pause_signature = PauseSignature::from_intervals(&ikis);
        fp.dwell_distribution = DwellDistribution::from_samples(samples);
        fp.flight_distribution = FlightTimeDistribution::from_samples(samples);
        fp.digraph_profile = DigraphProfile::from_samples(samples);
        fp.session_signature.compute_burst_metrics(&ikis);

        if ikis.len() >= 20 {
            fp.hurst_exponent = crate::analysis::hurst::compute_hurst_rs(&ikis)
                .ok()
                .map(|h| h.exponent);
        }

        fp.update_confidence();

        fp
    }

    /// Weighted merge of `other` into `self` by sample count.
    pub fn merge(&mut self, other: &ActivityFingerprint) {
        log::debug!("ActivityFingerprint::merge: self_samples={}, other_samples={}", self.sample_count, other.sample_count);
        let total = self.sample_count + other.sample_count;
        if total == 0 {
            return;
        }

        let self_weight = self.sample_count as f64 / total as f64;
        let other_weight = other.sample_count as f64 / total as f64;

        self.iki_distribution
            .merge(&other.iki_distribution, self_weight, other_weight);
        self.zone_profile
            .merge(&other.zone_profile, self_weight, other_weight);
        self.pause_signature
            .merge(&other.pause_signature, self_weight, other_weight);
        self.dwell_distribution.weighted_merge(
            &other.dwell_distribution,
            self_weight,
            other_weight,
        );
        self.flight_distribution.weighted_merge(
            &other.flight_distribution,
            self_weight,
            other_weight,
        );
        self.digraph_profile
            .weighted_merge(&other.digraph_profile, self_weight, other_weight);
        self.circadian_pattern.merge(&other.circadian_pattern);
        self.session_signature.merge(&other.session_signature);

        self.hurst_exponent = match (self.hurst_exponent, other.hurst_exponent) {
            (Some(a), Some(b)) => Some(a * self_weight + b * other_weight),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        self.phys_ratio = match (self.phys_ratio, other.phys_ratio) {
            (Some(a), Some(b)) => Some(a * self_weight + b * other_weight),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        match (&mut self.mouse_idle_stats, &other.mouse_idle_stats) {
            (Some(ref mut self_stats), Some(other_stats)) => {
                self_stats.merge(other_stats);
            }
            (None, Some(other_stats)) => {
                self.mouse_idle_stats = Some(other_stats.clone());
            }
            _ => {}
        }

        self.sample_count = total;
        self.update_confidence();
    }

    /// Set hardware entropy ratio (clamped to 0.0-1.0).
    pub fn set_phys_ratio(&mut self, ratio: f64) {
        self.phys_ratio = Some(crate::utils::Probability::clamp(ratio).get());
    }

    /// Attach mouse idle jitter stats as an additional biometric signal.
    pub fn set_mouse_idle_stats(&mut self, stats: crate::platform::MouseIdleStats) {
        self.mouse_idle_stats = Some(stats);
    }

    /// Return a reference to mouse idle jitter stats, if attached.
    pub fn mouse_idle_stats(&self) -> Option<&crate::platform::MouseIdleStats> {
        self.mouse_idle_stats.as_ref()
    }

    /// Weighted similarity score (0.0-1.0) against another fingerprint.
    pub fn similarity(&self, other: &ActivityFingerprint) -> f64 {
        log::debug!("ActivityFingerprint::similarity: self_id={}, other_id={}", self.id, other.id);
        let iki_sim = self.iki_distribution.similarity(&other.iki_distribution);
        let zone_sim = self.zone_profile.similarity(&other.zone_profile);
        let pause_sim = self.pause_signature.similarity(&other.pause_signature);
        let dwell_sim = <DwellDistribution as WeightedDistribution>::similarity(
            &self.dwell_distribution,
            &other.dwell_distribution,
        );
        let flight_sim = <FlightTimeDistribution as WeightedDistribution>::similarity(
            &self.flight_distribution,
            &other.flight_distribution,
        );
        let digraph_sim = self.digraph_profile.similarity(&other.digraph_profile);

        let mut score = iki_sim * 0.22
            + zone_sim * 0.22
            + pause_sim * 0.18
            + dwell_sim * 0.08
            + flight_sim * 0.10
            + digraph_sim * 0.15;

        match (self.hurst_exponent, other.hurst_exponent) {
            (Some(h1), Some(h2)) => {
                let hurst_sim = 1.0 - (h1 - h2).abs().min(1.0);
                score += hurst_sim * 0.05;
            }
            _ => {
                // Redistribute hurst's 0.05 weight across the other 6 dimensions
                // by scaling them up proportionally: each weight * (1.0 / 0.95)
                let scale = 1.0 / 0.95;
                score = iki_sim * 0.22 * scale
                    + zone_sim * 0.22 * scale
                    + pause_sim * 0.18 * scale
                    + dwell_sim * 0.08 * scale
                    + flight_sim * 0.10 * scale
                    + digraph_sim * 0.15 * scale;
            }
        }

        crate::utils::Probability::clamp(score).get()
    }

    /// Update per-dimension and overall confidence from current state.
    fn update_confidence(&mut self) {
        let has_dwell = self.dwell_distribution.mean > 0.0;
        let has_flight = self.flight_distribution.mean > 0.0;
        let has_hurst = self.hurst_exponent.is_some();

        self.dimension_confidence = DimensionConfidence::from_sample_count(
            self.sample_count,
            has_dwell,
            has_flight,
            has_hurst,
            self.circadian_pattern.total_samples,
        );
        self.confidence = self.dimension_confidence.overall();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_samples(intervals_ms: &[i64]) -> Vec<SimpleJitterSample> {
        let mut samples = Vec::new();
        let mut ts = 0i64;

        for (i, &interval) in intervals_ms.iter().enumerate() {
            samples.push(SimpleJitterSample {
                timestamp_ns: ts,
                duration_since_last_ns: if i == 0 {
                    0
                } else {
                    interval as u64 * 1_000_000
                },
                zone: (i % 8) as u8,
                ..Default::default()
            });
            ts += interval * 1_000_000;
        }

        samples
    }

    #[test]
    fn test_activity_fingerprint_creation() {
        let samples = make_samples(&[0, 150, 200, 180, 220, 190, 210, 175, 195, 185]);
        let fp = ActivityFingerprint::from_samples(&samples);

        assert!(fp.iki_distribution.mean > 0.0);
        assert!(fp.sample_count > 0);
    }

    #[test]
    fn test_fingerprint_similarity() {
        let samples1 = make_samples(&[0, 150, 200, 180, 220, 190, 210, 175, 195, 185]);
        let samples2 = make_samples(&[0, 155, 195, 185, 215, 195, 205, 180, 190, 190]);
        let samples3 = make_samples(&[0, 50, 50, 50, 50, 50, 50, 50, 50, 50]);

        let fp1 = ActivityFingerprint::from_samples(&samples1);
        let fp2 = ActivityFingerprint::from_samples(&samples2);
        let fp3 = ActivityFingerprint::from_samples(&samples3);

        let sim12 = fp1.similarity(&fp2);
        let sim13 = fp1.similarity(&fp3);

        assert!(sim12 > sim13, "Similar patterns should be more similar");
    }

    #[test]
    fn test_iki_distribution() {
        let intervals = vec![100.0, 150.0, 200.0, 180.0, 120.0];
        let dist = IkiDistribution::from_intervals(&intervals);

        assert!(dist.mean > 0.0);
        assert!(dist.std_dev > 0.0);
    }

    #[test]
    fn test_accumulator() {
        let mut acc = ActivityFingerprintAccumulator::new();

        for i in 0..100 {
            acc.add_sample(&SimpleJitterSample {
                timestamp_ns: i * 200_000_000,
                duration_since_last_ns: 200_000_000,
                zone: (i % 8) as u8,
                ..Default::default()
            });
        }

        assert_eq!(acc.sample_count(), 100);
        let fp = acc.current_fingerprint();
        assert!(fp.sample_count > 0);
    }
}
