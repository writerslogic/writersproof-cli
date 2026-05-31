// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Signal-to-noise ratio analysis on inter-keystroke interval (IKI) data.
//!
//! Human typing produces a mix of low-frequency cadence patterns (signal)
//! and high-frequency jitter (noise). Synthetic input that is "too clean"
//! will have an abnormally high SNR across all windows.

use serde::{Deserialize, Serialize};

/// Comprehensive error type for SNR analysis.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnrError {
    #[error("Insufficient IKI samples: found {found}, minimum {required} required")]
    InsufficientSamples { found: usize, required: usize },
    #[error("Insufficient sliding windows for SNR analysis")]
    InsufficientWindows,
    #[error("Input contains non-finite values")]
    NonFiniteValues,
}

/// SNR above this threshold across all windows indicates synthetic input.
const SNR_SYNTHETIC_THRESHOLD_DB: f64 = 20.0;

/// Maximum SNR value in dB to avoid infinity in serialized output.
const MAX_SNR_DB: f64 = 100.0;

/// Sliding window size in samples.
const WINDOW_SIZE: usize = 32;

/// Minimum IKI samples required for SNR analysis.
const MIN_SAMPLES: usize = 64;

/// Result of signal-to-noise ratio analysis on IKI data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnrAnalysis {
    /// Overall SNR in decibels.
    pub snr_db: f64,
    /// Per-window SNR values: global_signal_power / window_variance.
    ///
    /// High values indicate low jitter relative to the overall cadence trend.
    /// Note: Not independent per-window measurements, but rather comparisons
    /// of each window's noise to the global signal trend (low-frequency component).
    pub windowed_snr: Vec<f64>,
    /// Whether SNR is flagged as anomalous (too clean = synthetic).
    pub flagged: bool,
}

/// Convert signal/noise powers to dB, clamped to ±MAX_SNR_DB.
/// Handles zero/negative edge cases: zero noise → +MAX_SNR_DB, zero signal → -MAX_SNR_DB.
fn snr_db_capped(signal_power: f64, noise_power: f64) -> f64 {
    if noise_power <= 0.0 {
        MAX_SNR_DB
    } else if signal_power <= 0.0 {
        -MAX_SNR_DB
    } else {
        (10.0 * (signal_power / noise_power).log10()).clamp(-MAX_SNR_DB, MAX_SNR_DB)
    }
}

/// Compute SNR across sliding windows of IKI data.
///
/// Signal power = variance of window means (low-frequency cadence).
/// Noise power = mean of window variances (high-frequency jitter).
pub fn analyze_snr(iki_intervals_ns: &[f64]) -> Result<SnrAnalysis, SnrError> {
    let len = iki_intervals_ns.len();
    if len < MIN_SAMPLES {
        return Err(SnrError::InsufficientSamples {
            found: len,
            required: MIN_SAMPLES,
        });
    }
    crate::utils::require_all_finite(iki_intervals_ns, "snr")
        .map_err(|_| SnrError::NonFiniteValues)?;

    // 50% overlapping windows (step = WINDOW_SIZE/2). Overlap inflates the
    // reported SNR by approximately 3 dB compared to non-overlapping windows
    // because adjacent windows share half their samples, reducing variance.
    const STEP: usize = WINDOW_SIZE / 2;
    let expected_windows = (len - WINDOW_SIZE) / STEP + 1;
    let mut window_stats = Vec::with_capacity(expected_windows);
    let mut sum_of_means = 0.0;
    let mut sum_of_variances = 0.0;

    // Single pass to collect means and variances, avoiding separate allocations
    for w in iki_intervals_ns.windows(WINDOW_SIZE).step_by(STEP) {
        let (mean, variance) = crate::utils::stats::mean_and_variance(w);
        window_stats.push((mean, variance));
        sum_of_means += mean;
        sum_of_variances += variance;
    }

    let num_windows = window_stats.len();
    if num_windows < 2 {
        return Err(SnrError::InsufficientWindows);
    }

    // Signal power: variance of the window means (low-frequency component)
    let grand_mean = sum_of_means / num_windows as f64;
    let signal_power = window_stats
        .iter()
        .map(|&(m, _)| (m - grand_mean).powi(2))
        .sum::<f64>()
        / num_windows as f64;

    // Noise power: mean of the window variances (high-frequency component)
    let noise_power = sum_of_variances / num_windows as f64;

    let snr_db = snr_db_capped(signal_power, noise_power);

    // Second pass to compute per-window SNR and build the return vector
    let windowed_snr: Vec<f64> = window_stats
        .iter()
        .map(|&(_, var)| snr_db_capped(signal_power, var))
        .collect();

    // If all windows exceed threshold, the overall SNR is mathematically guaranteed to exceed it
    // (since snr_db is the ratio of signal_power to mean(window_variances)).
    // Flagging occurs only when all windows show the "too clean" pattern consistently.
    let flagged = windowed_snr.iter().all(|&s| s > SNR_SYNTHETIC_THRESHOLD_DB);

    Ok(SnrAnalysis {
        snr_db,
        windowed_snr,
        flagged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snr_human_like_data() {
        let mut data = Vec::new();
        for i in 0..200 {
            let base = 150_000_000.0;
            let jitter =
                ((i as f64 * 0.7).sin() * 50_000_000.0) + ((i as f64 * 2.3).cos() * 30_000_000.0);
            data.push(base + jitter);
        }
        let result = analyze_snr(&data).unwrap();
        assert!(
            !result.flagged,
            "Human-like data should not be flagged, SNR={:.1}",
            result.snr_db
        );
    }

    #[test]
    fn test_snr_too_few_samples() {
        let data: Vec<f64> = (0..30).map(|i| i as f64 * 1000.0).collect();
        assert!(matches!(
            analyze_snr(&data),
            Err(SnrError::InsufficientSamples { .. })
        ));
    }

    #[test]
    fn test_snr_rejects_nan() {
        let mut data: Vec<f64> = (0..100).map(|i| 150_000_000.0 + i as f64).collect();
        data[50] = f64::NAN;
        assert!(matches!(analyze_snr(&data), Err(SnrError::NonFiniteValues)));
    }

    #[test]
    fn test_snr_rejects_infinity() {
        let mut data: Vec<f64> = (0..100).map(|i| 150_000_000.0 + i as f64).collect();
        data[25] = f64::INFINITY;
        assert!(matches!(analyze_snr(&data), Err(SnrError::NonFiniteValues)));
    }

    #[test]
    fn test_snr_robotic_constant() {
        let data: Vec<f64> = vec![100_000_000.0; 200];
        let result = analyze_snr(&data).unwrap();
        assert!(result.flagged, "Constant intervals should be flagged");
    }
}
