// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Hurst exponent calculation for time series analysis.
//!
//! The Hurst exponent (H) characterizes the long-term memory of time series:
//! - H ≈ 0.5: Random walk (white noise) - no memory
//! - H > 0.5: Persistent/trending behavior
//! - H < 0.5: Anti-persistent/mean-reverting
//!
//! Human typing patterns typically exhibit H ≈ 0.7 (mild persistence),
//! reflecting cognitive rhythm and motor control patterns.
//!
//! RFC draft-condrey-rats-pop-01 specifies:
//! - Reject H ≈ 0.5 (pure random - likely synthetic)
//! - Reject H ≈ 1.0 (fully predictable - likely scripted)
//! - Accept H ∈ [0.55, 0.85] as biologically plausible

use serde::{Deserialize, Serialize};
use std::fmt;

/// Comprehensive error type for Hurst analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HurstError {
    InsufficientDataPoints { found: usize, required: usize },
    InsufficientWindows,
    InsufficientScales,
    RegressionFailed(String),
    RegressionProducedNaN,
    NonFiniteValues,
}

impl fmt::Display for HurstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientDataPoints { found, required } => write!(
                f,
                "Insufficient data points: found {}, minimum {} required",
                found, required
            ),
            Self::InsufficientWindows => write!(f, "Insufficient window sizes for reliable estimation"),
            Self::InsufficientScales => write!(f, "Insufficient scales for reliable DFA estimation"),
            Self::RegressionFailed(msg) => write!(f, "Linear regression failed: {}", msg),
            Self::RegressionProducedNaN => write!(
                f,
                "Regression produced NaN/Inf; likely caused by constant variance or zero fluctuation"
            ),
            Self::NonFiniteValues => write!(f, "Input contains non-finite values"),
        }
    }
}

impl std::error::Error for HurstError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HurstAnalysis {
    pub exponent: f64,
    pub std_error: f64,
    pub r_squared: f64,
    pub interpretation: HurstInterpretation,
    pub is_valid: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HurstInterpretation {
    WhiteNoise,
    AntiPersistent,
    Persistent,
    HighlyPredictable,
}

impl HurstAnalysis {
    pub const MIN_VALID: f64 = 0.55;
    pub const MAX_VALID: f64 = 0.85;
    pub const WHITE_NOISE_TOLERANCE: f64 = 0.05;
    pub const SUSPICIOUSLY_PREDICTABLE: f64 = 0.95;

    pub fn is_biologically_plausible(&self) -> bool {
        self.exponent >= Self::MIN_VALID && self.exponent <= Self::MAX_VALID
    }

    pub fn is_white_noise(&self) -> bool {
        (self.exponent - 0.5).abs() < Self::WHITE_NOISE_TOLERANCE
    }

    pub fn is_suspiciously_predictable(&self) -> bool {
        self.exponent > Self::SUSPICIOUSLY_PREDICTABLE
    }
}

const RS_MIN_DATA_POINTS: usize = 20;
const RS_MIN_WINDOW: usize = 8;
const DFA_MIN_DATA_POINTS: usize = 32;
const DFA_MIN_SCALE: usize = 8;

fn classify_hurst_exponent(exponent: f64) -> (HurstInterpretation, bool) {
    let interpretation = if (exponent - 0.5).abs() < HurstAnalysis::WHITE_NOISE_TOLERANCE {
        HurstInterpretation::WhiteNoise
    } else if exponent < 0.5 {
        HurstInterpretation::AntiPersistent
    } else if exponent <= HurstAnalysis::MAX_VALID {
        HurstInterpretation::Persistent
    } else {
        HurstInterpretation::HighlyPredictable
    };

    let is_valid = (HurstAnalysis::MIN_VALID..=HurstAnalysis::MAX_VALID).contains(&exponent);

    (interpretation, is_valid)
}

pub fn compute_hurst_rs(data: &[f64]) -> Result<HurstAnalysis, HurstError> {
    let n = data.len();
    if n < RS_MIN_DATA_POINTS {
        return Err(HurstError::InsufficientDataPoints {
            found: n,
            required: RS_MIN_DATA_POINTS,
        });
    }

    if !data.iter().all(|v| v.is_finite()) {
        return Err(HurstError::NonFiniteValues);
    }

    let mut log_n_vec = Vec::with_capacity(16);
    let mut log_rs_vec = Vec::with_capacity(16);

    let min_window = RS_MIN_WINDOW.min(n / 8).max(4);
    let max_window = n / 4;

    let mut window_size = min_window;
    while window_size <= max_window {
        let rs = compute_rs_for_window(data, window_size);
        if rs > 0.0 {
            log_n_vec.push((window_size as f64).ln());
            log_rs_vec.push(rs.ln());
        }
        window_size *= 2;
    }

    if log_n_vec.len() < 3 {
        return Err(HurstError::InsufficientWindows);
    }

    let (slope, _intercept, r_squared, std_error) = linear_regression(&log_n_vec, &log_rs_vec)
        .map_err(|e| HurstError::RegressionFailed(e.to_string()))?;

    if !slope.is_finite() || !r_squared.is_finite() || !std_error.is_finite() {
        return Err(HurstError::RegressionProducedNaN);
    }

    let exponent = crate::utils::Probability::clamp(slope).get();

    let (interpretation, is_valid) = classify_hurst_exponent(exponent);

    Ok(HurstAnalysis {
        exponent,
        std_error,
        r_squared,
        interpretation,
        is_valid,
    })
}

fn compute_rs_for_window(data: &[f64], window_size: usize) -> f64 {
    let n = data.len();
    if window_size > n || window_size < 2 {
        return 0.0;
    }

    let num_windows = n / window_size;
    if num_windows == 0 {
        return 0.0;
    }

    let mut rs_sum = 0.0;
    let mut valid_windows = 0;

    for i in 0..num_windows {
        let start = i * window_size;
        let end = start + window_size;
        let window = &data[start..end];

        let mean: f64 = window.iter().sum::<f64>() / window_size as f64;

        let mut min_cumsum = f64::INFINITY;
        let mut max_cumsum = f64::NEG_INFINITY;
        let mut cumsum = 0.0;
        let mut variance_sum = 0.0;

        // Compute min/max of cumulative sum and variance in a single pass.
        // Eliminates O(N) allocation of intermediate cumulative vector.
        for &x in window {
            let diff = x - mean;
            cumsum += diff;
            min_cumsum = min_cumsum.min(cumsum);
            max_cumsum = max_cumsum.max(cumsum);
            variance_sum += diff * diff;
        }

        let range = max_cumsum - min_cumsum;
        let std_dev = (variance_sum / (window_size - 1) as f64).sqrt();

        if std_dev > 0.0 {
            let rs = range / std_dev;
            if rs.is_finite() {
                rs_sum += rs;
                valid_windows += 1;
            }
        }
    }

    if valid_windows > 0 {
        rs_sum / valid_windows as f64
    } else {
        0.0
    }
}

pub fn compute_hurst_dfa(data: &[f64]) -> Result<HurstAnalysis, HurstError> {
    let n = data.len();
    if n < DFA_MIN_DATA_POINTS {
        return Err(HurstError::InsufficientDataPoints {
            found: n,
            required: DFA_MIN_DATA_POINTS,
        });
    }

    let mean: f64 = data.iter().sum::<f64>() / n as f64;
    if !mean.is_finite() {
        return Err(HurstError::NonFiniteValues);
    }

    let mut profile = Vec::with_capacity(n);
    let mut cumsum = 0.0;
    for &x in data {
        cumsum += x - mean;
        profile.push(cumsum);
    }

    let mut log_scales = Vec::with_capacity(16);
    let mut log_fluct = Vec::with_capacity(16);

    let min_scale = DFA_MIN_SCALE;
    let max_scale = n / 4;

    let mut scale = min_scale;
    while scale <= max_scale {
        let f = compute_dfa_fluctuation(&profile, scale);
        if f > 0.0 {
            log_scales.push((scale as f64).ln());
            log_fluct.push(f.ln());
        }
        scale = (scale as f64 * 1.5).ceil() as usize;
    }

    if log_scales.len() < 3 {
        return Err(HurstError::InsufficientScales);
    }

    let (slope, _intercept, r_squared, std_error) = linear_regression(&log_scales, &log_fluct)
        .map_err(|e| HurstError::RegressionFailed(e.to_string()))?;

    if !slope.is_finite() || !r_squared.is_finite() || !std_error.is_finite() {
        return Err(HurstError::RegressionProducedNaN);
    }

    // DFA alpha can reach 2.0 (Brownian ~1.5, ballistic ~2.0)
    let exponent = slope.clamp(0.0, 2.0);

    let (interpretation, is_valid) = classify_hurst_exponent(exponent);

    Ok(HurstAnalysis {
        exponent,
        std_error,
        r_squared,
        interpretation,
        is_valid,
    })
}

fn compute_dfa_fluctuation(profile: &[f64], scale: usize) -> f64 {
    let n = profile.len();
    if scale > n || scale < 4 {
        return 0.0;
    }

    let num_segments = n / scale;
    if num_segments == 0 {
        return 0.0;
    }

    let mut total_variance = 0.0;

    for i in 0..num_segments {
        let start = i * scale;
        let end = start + scale;
        let segment = &profile[start..end];

        let detrended_variance = detrend_variance(segment);
        total_variance += detrended_variance;
    }

    (total_variance / num_segments as f64).sqrt()
}

/// Computes the variance of the residuals of a linear regression over the segment.
/// Uses mathematical expansion of Residual Sum of Squares (RSS) to compute slope
/// and variance simultaneously in a single highly-optimized O(N) pass.
fn detrend_variance(segment: &[f64]) -> f64 {
    let n = segment.len();
    if n < 2 {
        return 0.0;
    }

    let n_f = n as f64;
    let mut sum_y = 0.0;
    let mut sum_iy = 0.0;
    let mut sum_y2 = 0.0;

    // Single pass accumulation for linear regression components
    for (i, &y) in segment.iter().enumerate() {
        sum_y += y;
        sum_iy += (i as f64) * y;
        sum_y2 += y * y;
    }

    let mean_x = (n_f - 1.0) / 2.0;

    // S_xx is mathematically constant for indices [0, 1, ..., n-1]
    let s_xx = n_f * (n_f * n_f - 1.0) / 12.0;
    let s_xy = sum_iy - mean_x * sum_y;
    let s_yy = sum_y2 - (sum_y * sum_y) / n_f;

    let a = if s_xx > 0.0 { s_xy / s_xx } else { 0.0 };

    // Residual Sum of Squares = S_yy - a * S_xy
    // `.max(0.0)` defends against slight floating-point underflow for perfect collinearity
    let rss = (s_yy - a * s_xy).max(0.0);

    rss / n_f
}

use super::stats::linear_regression;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hurst_white_noise() {
        use rand::Rng;
        let mut rng = rand::rng();
        let data: Vec<f64> = (0..500).map(|_| rng.random::<f64>()).collect();

        let result = compute_hurst_rs(&data).unwrap();
        assert!(
            result.exponent > 0.2 && result.exponent < 0.8,
            "White noise Hurst should be near 0.5, got {}",
            result.exponent
        );
    }

    #[test]
    fn test_hurst_trending() {
        use rand::Rng;
        let mut rng = rand::rng();
        let mut cumsum = 0.0;
        let data: Vec<f64> = (0..500)
            .map(|_| {
                cumsum += rng.random::<f64>() - 0.5;
                cumsum
            })
            .collect();

        let result = compute_hurst_rs(&data).unwrap();
        assert!(
            result.exponent > 0.7,
            "Trending data Hurst should be > 0.7, got {}",
            result.exponent
        );
    }

    #[test]
    fn test_hurst_insufficient_data() {
        let data: Vec<f64> = vec![1.0, 2.0, 3.0];
        let result = compute_hurst_rs(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_hurst_validity_check() {
        let analysis = HurstAnalysis {
            exponent: 0.7,
            std_error: 0.05,
            r_squared: 0.95,
            interpretation: HurstInterpretation::Persistent,
            is_valid: true,
        };

        assert!(analysis.is_biologically_plausible());
        assert!(!analysis.is_white_noise());
        assert!(!analysis.is_suspiciously_predictable());
    }

    #[test]
    fn test_dfa_basic() {
        let data: Vec<f64> = (0..100)
            .map(|i| (i as f64).sin() + 0.1 * i as f64)
            .collect();
        let result = compute_hurst_dfa(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_linear_regression() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![2.0, 4.0, 6.0, 8.0, 10.0];

        let (slope, intercept, r_squared, _) = linear_regression(&x, &y).unwrap();

        assert!((slope - 2.0).abs() < 0.001);
        assert!(intercept.abs() < 0.001);
        assert!((r_squared - 1.0).abs() < 0.001);
    }
}
