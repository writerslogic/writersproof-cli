// SPDX-License-Identifier: Apache-2.0

use crate::forensics::transcription;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForensicVerdict {
    /// High entropy, valid causality, non-linear composition.
    V1VerifiedHuman,
    /// Valid timing with minor causality drift (e.g., clock skew).
    V2LikelyHuman,
    /// Low entropy or high linearity — potential transcription.
    V3Suspicious,
    /// Perfect timing uniformity — histogram attack or bot.
    V4LikelySynthetic,
    /// HMAC causality lock broken — confirmed tampering.
    V5ConfirmedForgery,
    /// Not enough data to make a determination.
    V6InsufficientData,
}

impl ForensicVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForensicVerdict::V1VerifiedHuman => "V1_VerifiedHuman",
            ForensicVerdict::V2LikelyHuman => "V2_LikelyHuman",
            ForensicVerdict::V3Suspicious => "V3_Suspicious",
            ForensicVerdict::V4LikelySynthetic => "V4_LikelySynthetic",
            ForensicVerdict::V5ConfirmedForgery => "V5_ConfirmedForgery",
            ForensicVerdict::V6InsufficientData => "V6_InsufficientData",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::V1VerifiedHuman => "Verified Human",
            Self::V2LikelyHuman => "Likely Human",
            Self::V3Suspicious => "Inconsistent Evidence",
            Self::V4LikelySynthetic => "Process Not Verified",
            Self::V5ConfirmedForgery => "Evidence Tampered",
            Self::V6InsufficientData => "Insufficient Data",
        }
    }

    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            ForensicVerdict::V1VerifiedHuman | ForensicVerdict::V2LikelyHuman
        )
    }
}

impl std::fmt::Display for ForensicVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForensicFlag {
    /// HMAC causality lock broken.
    CausalityBroken,
    /// Timing intervals are perfectly uniform.
    AdversarialCollapse,
    /// Timing entropy is too low (mechanical regularity).
    LowEntropy,
    /// Timing entropy is too high (noise injection).
    HighEntropy,
    /// Timing lacks long-range dependence (white noise).
    WhiteNoiseTiming,
    /// Timing is too predictable (scripted).
    PredictableTiming,
    /// High linearity in interaction patterns.
    HighLinearity,
    /// Interaction patterns indicate transcription.
    TranscriptionPattern,
    /// Insufficient data for full analysis.
    InsufficientData,
}

impl ForensicFlag {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForensicFlag::CausalityBroken => "CAUSALITY_BROKEN",
            ForensicFlag::AdversarialCollapse => "ADVERSARIAL_COLLAPSE",
            ForensicFlag::LowEntropy => "LOW_ENTROPY",
            ForensicFlag::HighEntropy => "HIGH_ENTROPY",
            ForensicFlag::WhiteNoiseTiming => "WHITE_NOISE",
            ForensicFlag::PredictableTiming => "PREDICTABLE_TIMING",
            ForensicFlag::HighLinearity => "HIGH_LINEARITY",
            ForensicFlag::TranscriptionPattern => "TRANSCRIPTION_PATTERN",
            ForensicFlag::InsufficientData => "INSUFFICIENT_DATA",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicAnalysis {
    pub verdict: ForensicVerdict,
    pub flags: Vec<ForensicFlag>,
    pub coefficient_of_variation: f64,
    pub linearity_score: Option<f64>,
    pub hurst_exponent: Option<f64>,
    pub checkpoint_count: usize,
    pub chain_duration_secs: u64,
    pub explanation: String,
}

impl ForensicAnalysis {
    fn new(
        verdict: ForensicVerdict,
        cv: f64,
        checkpoint_count: usize,
        chain_duration_secs: u64,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            verdict,
            flags: Vec::new(),
            coefficient_of_variation: cv,
            linearity_score: None,
            hurst_exponent: None,
            checkpoint_count,
            chain_duration_secs,
            explanation: explanation.into(),
        }
    }

    fn with_flags(mut self, flags: Vec<ForensicFlag>) -> Self {
        self.flags = flags;
        self
    }

    fn with_hurst(mut self, h: Option<f64>) -> Self {
        self.hurst_exponent = h;
        self
    }

    fn with_linearity(mut self, l: Option<f64>) -> Self {
        self.linearity_score = l;
        self
    }
}

// --- Forensic threshold constants ---
// Empirical calibration values from keystroke dynamics literature.
// See draft-condrey-cpoe-appraisal §forensic-assessment for rationale.

/// CV below this indicates mechanically regular timing (bot/replay).
const CV_MIN: f64 = 0.15;
/// CV above this indicates chaotic noise injection.
const CV_MAX: f64 = 0.80;
/// Hurst exponent below this indicates white-noise (non-human) timing.
const HURST_MIN: f64 = 0.45;
/// Hurst exponent above this indicates highly predictable (scripted) timing.
const HURST_MAX: f64 = 0.90;
/// Hurst range for "ideal" human composition (no minor anomaly flag).
const HURST_IDEAL_MIN: f64 = 0.55;
const HURST_IDEAL_MAX: f64 = 0.85;
/// Linearity above this combined with burst length triggers transcription flag.
const LINEARITY_TRANSCRIPTION: f64 = 0.92;
/// Average burst length above this (with high linearity) indicates transcription.
const BURST_TRANSCRIPTION: f64 = 15.0;
/// Linearity above this (but below transcription) triggers minor anomaly.
const LINEARITY_ANOMALY: f64 = 0.85;
/// Minimum intervals required for Hurst exponent estimation.
const MIN_INTERVALS_FOR_HURST: usize = 10;

pub struct ForensicsEngine {
    pub inter_checkpoint_intervals: Vec<f64>,
    pub causality_chain_valid: bool,
    pub transcription_data: Option<transcription::TranscriptionData>,
}

impl ForensicsEngine {
    /// Build from a sequence of timestamps (milliseconds since epoch).
    ///
    /// Timestamps should be monotonically non-decreasing. Out-of-order
    /// timestamps produce zero-clamped intervals to avoid negative values
    /// corrupting statistical analysis.
    pub fn from_timestamps(timestamps: &[u64], causality_valid: bool) -> Self {
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| {
                if w[1] < w[0] {
                    log::warn!(
                        "out-of-order checkpoint timestamps: {} followed by {} (delta={}); clamping to zero",
                        w[0], w[1], w[0] - w[1]
                    );
                }
                w[1].saturating_sub(w[0]) as f64
            })
            .collect();

        Self {
            inter_checkpoint_intervals: intervals,
            causality_chain_valid: causality_valid,
            transcription_data: None,
        }
    }

    pub fn with_transcription_data(mut self, data: transcription::TranscriptionData) -> Self {
        self.transcription_data = Some(data);
        self
    }

    pub fn analyze(&self) -> ForensicAnalysis {
        let checkpoint_count = self.inter_checkpoint_intervals.len() + 1;
        let dur_ms = self.inter_checkpoint_intervals.iter().sum::<f64>().max(0.0);
        let dur = (dur_ms / 1000.0) as u64;
        let fa = |v, cv, msg: String, flags: Vec<ForensicFlag>| {
            ForensicAnalysis::new(v, cv, checkpoint_count, dur, msg).with_flags(flags)
        };

        let mut flags = Vec::new();

        // Phase 1: structural checks (causality, minimum data)
        if !self.causality_chain_valid {
            flags.push(ForensicFlag::CausalityBroken);
            return fa(
                ForensicVerdict::V5ConfirmedForgery,
                0.0,
                "HMAC causality lock broken".into(),
                flags,
            );
        }
        if self.inter_checkpoint_intervals.len() < 3 {
            flags.push(ForensicFlag::InsufficientData);
            return fa(
                ForensicVerdict::V6InsufficientData,
                0.0,
                "Insufficient checkpoints for full forensic analysis".into(),
                flags,
            );
        }

        // Phase 2: timing distribution checks
        let cv = self.compute_coefficient_of_variation();
        if let Some(result) = self.check_timing_distribution(cv, checkpoint_count, dur) {
            return result;
        }

        // Phase 3: long-range dependence (Hurst exponent)
        let hurst = self.compute_hurst();
        if let Some(result) = self.check_hurst(hurst, cv, checkpoint_count, dur) {
            return result;
        }

        // Phase 4: transcription detection
        let linearity = self.compute_linearity();
        if let Some(result) = self.check_transcription(linearity, hurst, cv, checkpoint_count, dur)
        {
            return result;
        }

        // Phase 5: minor anomaly detection
        if hurst.is_some_and(|h| !(HURST_IDEAL_MIN..=HURST_IDEAL_MAX).contains(&h)) {
            let h = hurst.unwrap();
            if h < HURST_IDEAL_MIN {
                flags.push(ForensicFlag::WhiteNoiseTiming);
            } else if h > HURST_IDEAL_MAX {
                flags.push(ForensicFlag::PredictableTiming);
            }
        }
        if linearity.is_some_and(|l| l > LINEARITY_ANOMALY) {
            flags.push(ForensicFlag::HighLinearity);
        }

        if !flags.is_empty() {
            return fa(
                ForensicVerdict::V2LikelyHuman,
                cv,
                "Timing consistent with human composition, minor anomalies noted".into(),
                flags,
            )
            .with_hurst(hurst)
            .with_linearity(linearity);
        }

        fa(
            ForensicVerdict::V1VerifiedHuman,
            cv,
            "High entropy, valid causality, non-linear composition confirmed".into(),
            Vec::new(),
        )
        .with_hurst(hurst)
        .with_linearity(linearity)
    }

    fn check_timing_distribution(&self, cv: f64, n: usize, dur: u64) -> Option<ForensicAnalysis> {
        let fa = |v, cv, msg: String, flags: Vec<ForensicFlag>| {
            ForensicAnalysis::new(v, cv, n, dur, msg).with_flags(flags)
        };

        if self.detect_adversarial_collapse() {
            return Some(fa(
                ForensicVerdict::V4LikelySynthetic,
                cv,
                "Adversarial collapse: timing intervals are uniform (non-human)".into(),
                vec![ForensicFlag::AdversarialCollapse],
            ));
        }
        if cv < CV_MIN {
            return Some(fa(
                ForensicVerdict::V4LikelySynthetic,
                cv,
                format!(
                    "Timing entropy too low (CV={:.3}): automated generation",
                    cv
                ),
                vec![ForensicFlag::LowEntropy],
            ));
        }
        if cv > CV_MAX {
            return Some(fa(
                ForensicVerdict::V3Suspicious,
                cv,
                format!("Timing entropy too high (CV={:.3}): noise injection", cv),
                vec![ForensicFlag::HighEntropy],
            ));
        }
        None
    }

    fn compute_hurst(&self) -> Option<f64> {
        if self.inter_checkpoint_intervals.len() >= MIN_INTERVALS_FOR_HURST {
            Some(self.estimate_hurst_exponent())
        } else {
            None
        }
    }

    fn check_hurst(
        &self,
        hurst: Option<f64>,
        cv: f64,
        n: usize,
        dur: u64,
    ) -> Option<ForensicAnalysis> {
        let h = hurst?;
        let fa = |v, cv, msg: String, flags: Vec<ForensicFlag>| {
            ForensicAnalysis::new(v, cv, n, dur, msg)
                .with_flags(flags)
                .with_hurst(Some(h))
        };

        if h < HURST_MIN {
            return Some(fa(
                ForensicVerdict::V3Suspicious,
                cv,
                format!("White-noise timing (H={:.3}): non-human composition", h),
                vec![ForensicFlag::WhiteNoiseTiming],
            ));
        }
        if h > HURST_MAX {
            return Some(fa(
                ForensicVerdict::V3Suspicious,
                cv,
                format!("Highly predictable timing (H={:.3}): scripted input", h),
                vec![ForensicFlag::PredictableTiming],
            ));
        }
        None
    }

    fn compute_linearity(&self) -> Option<f64> {
        self.transcription_data.as_ref().map(|td| {
            let detector = transcription::TranscriptionDetector::from_data(td);
            detector.compute_linearity_score()
        })
    }

    fn check_transcription(
        &self,
        linearity: Option<f64>,
        hurst: Option<f64>,
        cv: f64,
        n: usize,
        dur: u64,
    ) -> Option<ForensicAnalysis> {
        let lin = linearity?;
        if lin <= LINEARITY_TRANSCRIPTION {
            return None;
        }
        let avg_burst = self
            .transcription_data
            .as_ref()
            .map(|td| td.avg_burst_length)
            .unwrap_or(0.0);

        if avg_burst > BURST_TRANSCRIPTION {
            let fa = ForensicAnalysis::new(
                ForensicVerdict::V3Suspicious,
                cv,
                n,
                dur,
                format!(
                    "High linearity ({:.3}) with long bursts ({:.1}): transcription",
                    lin, avg_burst
                ),
            )
            .with_flags(vec![
                ForensicFlag::HighLinearity,
                ForensicFlag::TranscriptionPattern,
            ]);
            return Some(fa.with_hurst(hurst).with_linearity(Some(lin)));
        }
        None
    }

    fn compute_coefficient_of_variation(&self) -> f64 {
        let n = self.inter_checkpoint_intervals.len();
        if n < 2 {
            return 0.0;
        }
        let nf = n as f64;
        let mean = self.inter_checkpoint_intervals.iter().sum::<f64>() / nf;
        if mean == 0.0 || !mean.is_finite() {
            return 0.0;
        }
        // Bessel's correction (n-1) for unbiased sample variance
        let variance = self
            .inter_checkpoint_intervals
            .iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / (nf - 1.0);
        let cv = variance.sqrt() / mean;
        // NaN/Inf from pathological inputs must not bypass downstream threshold checks
        if cv.is_finite() {
            cv
        } else {
            0.0
        }
    }

    fn detect_adversarial_collapse(&self) -> bool {
        let n = self.inter_checkpoint_intervals.len();
        if n < 3 {
            return false;
        }

        // Use the mean as reference instead of the first value to avoid
        // order-dependent bias.
        let mean = self.inter_checkpoint_intervals.iter().sum::<f64>() / n as f64;
        let tolerance = (mean.abs() * 0.01).max(0.001);

        self.inter_checkpoint_intervals
            .iter()
            .all(|&x| (x - mean).abs() < tolerance)
    }

    /// Rescaled range (R/S) method for Hurst exponent estimation.
    fn estimate_hurst_exponent(&self) -> f64 {
        let data = &self.inter_checkpoint_intervals;
        let n = data.len();

        if n < 10 {
            return 0.5;
        }

        let mut log_n_values = Vec::with_capacity(8);
        let mut log_rs_values = Vec::with_capacity(8);
        let mut cumdev = Vec::new();

        let mut block_size = 4;
        while block_size <= n / 2 {
            let num_blocks = n / block_size;
            let mut rs_sum = 0.0;
            let mut valid_blocks = 0usize;

            for b in 0..num_blocks {
                let block = &data[b * block_size..(b + 1) * block_size];
                let mean = block.iter().sum::<f64>() / block_size as f64;

                cumdev.clear();
                cumdev.reserve(block_size);
                let mut running = 0.0;
                for &val in block {
                    running += val - mean;
                    cumdev.push(running);
                }

                let (cmin, cmax) = cumdev
                    .iter()
                    .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| {
                        (lo.min(v), hi.max(v))
                    });
                let range = cmax - cmin;

                let std_dev = (block.iter().map(|&x| (x - mean).powi(2)).sum::<f64>()
                    / block_size as f64)
                    .sqrt();

                if std_dev > 0.0 {
                    rs_sum += range / std_dev;
                    valid_blocks += 1;
                }
            }

            if valid_blocks > 0 {
                let avg_rs = rs_sum / valid_blocks as f64;
                if avg_rs > 0.0 {
                    log_n_values.push((block_size as f64).ln());
                    log_rs_values.push(avg_rs.ln());
                }
            }

            block_size *= 2;
        }

        if log_n_values.len() < 2 {
            return 0.5;
        }

        let n_pts = log_n_values.len() as f64;
        let sum_x: f64 = log_n_values.iter().sum();
        let sum_y: f64 = log_rs_values.iter().sum();
        let sum_xy: f64 = log_n_values
            .iter()
            .zip(log_rs_values.iter())
            .map(|(x, y)| x * y)
            .sum();
        let sum_xx: f64 = log_n_values.iter().map(|x| x * x).sum();

        let denominator = n_pts * sum_xx - sum_x * sum_x;
        if denominator.abs() < f64::EPSILON {
            return 0.5;
        }

        let slope = (n_pts * sum_xy - sum_x * sum_y) / denominator;
        if slope.is_finite() {
            slope.clamp(0.0, 1.0)
        } else {
            0.5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_composition_passes() {
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![
                12.5, 8.3, 15.2, 6.1, 22.7, 15.8, 20.0, 9.4, 18.9, 14.2, 11.3, 25.1, 7.8, 19.6,
                13.4, 16.7, 10.2, 21.5, 8.9, 17.3,
            ],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert!(result.verdict.is_verified());
    }

    #[test]
    fn test_bot_uniform_timing_fails() {
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![10.0, 10.0, 10.0, 10.0, 10.0],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V4LikelySynthetic);
    }

    #[test]
    fn test_broken_causality_chain() {
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![12.5, 8.3, 45.2],
            causality_chain_valid: false,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V5ConfirmedForgery);
    }

    #[test]
    fn test_low_entropy_synthetic() {
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![10.0, 10.1, 10.0, 9.9, 10.1, 10.0],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V4LikelySynthetic);
    }

    #[test]
    fn test_insufficient_checkpoints_returns_insufficient() {
        // Fewer than 3 intervals should return InsufficientData, not Suspicious
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![5.0, 10.0],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V6InsufficientData);
    }

    #[test]
    fn test_high_cv_noise_injection_detected() {
        // Very high coefficient of variation (> 0.80) = noise injection
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![
                1.0, 500.0, 2.0, 800.0, 1.5, 600.0, 3.0, 900.0, 0.5, 700.0,
            ],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V3Suspicious);
    }

    #[test]
    fn test_from_timestamps_out_of_order_produces_zero_intervals() {
        // Decreasing timestamps should produce zero intervals via saturating_sub
        let engine = ForensicsEngine::from_timestamps(&[100, 90, 80], true);
        assert!(engine.inter_checkpoint_intervals.iter().all(|&x| x == 0.0));
    }

    #[test]
    fn test_from_timestamps_equal_timestamps() {
        // Equal timestamps should produce zero intervals
        let engine = ForensicsEngine::from_timestamps(&[100, 100, 100, 100], true);
        assert!(engine.inter_checkpoint_intervals.iter().all(|&x| x == 0.0));
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V4LikelySynthetic);
    }

    #[test]
    fn test_single_interval_insufficient() {
        let engine = ForensicsEngine::from_timestamps(&[0, 1000], true);
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V6InsufficientData);
    }

    #[test]
    fn test_empty_intervals() {
        let engine = ForensicsEngine::from_timestamps(&[], true);
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V6InsufficientData);
    }
}
