// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Statistical utility functions.

use std::fmt;

/// Comprehensive error type for statistical operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsError {
    InsufficientData { found: usize, required: usize },
    LengthMismatch { x_len: usize, y_len: usize },
    NoVariance,
    DegenerateRegression,
}

impl fmt::Display for StatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientData { found, required } => write!(
                f,
                "Insufficient data points: found {}, minimum {} required",
                found, required
            ),
            Self::LengthMismatch { x_len, y_len } => {
                write!(f, "Data length mismatch: X has {}, Y has {}", x_len, y_len)
            }
            Self::NoVariance => write!(f, "No variance in independent variable (X data)"),
            Self::DegenerateRegression => write!(f, "Degenerate regression: slope is NaN/Inf"),
        }
    }
}

impl std::error::Error for StatsError {}

/// Divide `a / b`, returning `fallback` when `b` is zero or the result is
/// not finite (NaN / Infinity).
#[inline]
pub fn safe_div(a: f64, b: f64, fallback: f64) -> f64 {
    if b == 0.0 {
        return fallback;
    }
    let r = a / b;
    if r.is_finite() {
        r
    } else {
        fallback
    }
}

/// Population skewness given pre-computed mean and std dev.
pub fn skewness(data: &[f64], mean: f64, std: f64) -> f64 {
    if std.abs() < f64::EPSILON || data.is_empty() {
        return 0.0;
    }
    let n = data.len() as f64;
    let sum_cubed: f64 = data.iter().map(|&x| ((x - mean) / std).powi(3)).sum();
    let result = sum_cubed / n;
    if result.is_finite() {
        result
    } else {
        0.0
    }
}

/// Excess kurtosis given pre-computed mean and std dev.
pub fn kurtosis(data: &[f64], mean: f64, std: f64) -> f64 {
    if std.abs() < f64::EPSILON || data.is_empty() {
        return 0.0;
    }
    let n = data.len() as f64;
    let sum_fourth: f64 = data.iter().map(|&x| ((x - mean) / std).powi(4)).sum();
    let result = sum_fourth / n - 3.0;
    if result.is_finite() {
        result
    } else {
        0.0
    }
}

/// Bhattacharyya coefficient between two f64 histograms.
///
/// If the slices differ in length, only the overlapping prefix is compared
/// and a warning is logged.
pub fn bhattacharyya_coefficient(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() {
        log::warn!(
            "bhattacharyya_coefficient: length mismatch (a={}, b={}); truncating to min",
            a.len(),
            b.len()
        );
    }
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x.max(0.0) * y.max(0.0)).sqrt())
        .sum()
}

/// Normalize a histogram in place so entries sum to 1.0.
///
/// If the histogram sums to zero (or negative), it is left unchanged.
pub fn normalize_histogram(hist: &mut [f64]) {
    crate::analysis::histogram::normalize(hist);
}

/// Weighted merge of histogram `b` into `a`: `a[i] = a[i] * a_weight + b[i] * b_weight`.
///
/// If `b` is shorter than `a`, the trailing bins in `a` are scaled by `a_weight` only
/// (equivalent to padding `b` with zeros). A warning is logged on length mismatch.
pub fn merge_histogram(a: &mut [f64], b: &[f64], a_weight: f64, b_weight: f64) {
    if a.len() != b.len() {
        log::warn!(
            "merge_histogram: length mismatch (a={}, b={}); padding shorter with zeros",
            a.len(),
            b.len()
        );
    }
    let overlap = a.len().min(b.len());
    for i in 0..overlap {
        a[i] = a[i] * a_weight + b[i] * b_weight;
    }
    for val in a.iter_mut().skip(overlap) {
        *val *= a_weight;
    }
}

/// Cosine similarity between two f64 slices.
///
/// Returns 0.0 if either vector has zero magnitude.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;
    for (&fa, &fb) in a.iter().zip(b.iter()) {
        dot += fa * fb;
        norm_a += fa * fa;
        norm_b += fb * fb;
    }
    if norm_a <= 0.0 || norm_b <= 0.0 {
        return 0.0;
    }
    dot / (norm_a.sqrt() * norm_b.sqrt())
}

/// Relative similarity: 1.0 when both zero, else `1 - |a-b|/(|a|+|b|+ε)`.
///
/// Returns 0.0 for NaN/infinite inputs. Output is always in [0.0, 1.0].
pub fn relative_similarity(a: f64, b: f64) -> f64 {
    if a == 0.0 && b == 0.0 {
        return 1.0;
    }
    let denom = a.abs() + b.abs() + 0.001;
    let r = 1.0 - (a - b).abs() / denom;
    crate::utils::Probability::clamp(r).get()
}

/// Linear regression returning (slope, intercept, r_squared, std_error).
pub fn linear_regression(x: &[f64], y: &[f64]) -> Result<(f64, f64, f64, f64), StatsError> {
    let n = x.len();
    if n < 2 {
        return Err(StatsError::InsufficientData {
            found: n,
            required: 2,
        });
    }
    if n != y.len() {
        return Err(StatsError::LengthMismatch {
            x_len: n,
            y_len: y.len(),
        });
    }

    let x_mean: f64 = x.iter().sum::<f64>() / n as f64;
    let y_mean: f64 = y.iter().sum::<f64>() / n as f64;

    let mut ss_xx = 0.0;
    let mut ss_xy = 0.0;
    let mut ss_yy = 0.0;

    for i in 0..n {
        let dx = x[i] - x_mean;
        let dy = y[i] - y_mean;
        ss_xx += dx * dx;
        ss_xy += dx * dy;
        ss_yy += dy * dy;
    }

    if ss_xx.abs() < f64::EPSILON {
        return Err(StatsError::NoVariance);
    }

    let slope = ss_xy / ss_xx;
    if !slope.is_finite() {
        return Err(StatsError::DegenerateRegression);
    }
    let intercept = y_mean - slope * x_mean;

    let r_squared = if ss_yy > 0.0 {
        let r2 = (ss_xy * ss_xy) / (ss_xx * ss_yy);
        if r2.is_finite() {
            r2
        } else {
            0.0
        }
    } else {
        1.0
    };

    let mut ss_res = 0.0;
    for i in 0..n {
        let predicted = slope * x[i] + intercept;
        ss_res += (y[i] - predicted).powi(2);
    }
    let mse = ss_res / (n - 2).max(1) as f64;
    let std_error = (mse / ss_xx).sqrt();
    let std_error = if std_error.is_finite() {
        std_error
    } else {
        0.0
    };

    Ok((slope, intercept, r_squared, std_error))
}

/// Squared Euclidean distance between two slices.
///
/// Only the overlapping prefix is used if lengths differ.
#[inline(always)]
pub fn sq_dist(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).powi(2)).sum()
}

/// Least-squares linear regression for y-only data where x = 0, 1, 2, ...
///
/// Returns (slope, intercept). Returns (0.0, mean(y)) on degenerate input.
pub fn linear_regression_y_only(y: &[f64]) -> (f64, f64) {
    let n = y.len() as f64;
    if n < 2.0 {
        let m = if y.is_empty() { 0.0 } else { y[0] };
        return (0.0, m);
    }

    let x_mean = (n - 1.0) / 2.0;
    let y_mean: f64 = y.iter().sum::<f64>() / n;

    let mut sum_xy = 0.0;
    let mut sum_x2 = 0.0;

    for (i, &val) in y.iter().enumerate() {
        let dx = i as f64 - x_mean;
        sum_xy += dx * (val - y_mean);
        sum_x2 += dx * dx;
    }

    if sum_x2 <= 0.0 {
        return (0.0, y_mean);
    }

    let slope = sum_xy / sum_x2;
    if !slope.is_finite() {
        return (0.0, y_mean);
    }
    let intercept = y_mean - slope * x_mean;
    (slope, intercept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_regression() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let (slope, intercept, r_squared, _) = linear_regression(&x, &y).unwrap();

        assert!((slope - 2.0).abs() < 1e-6);
        assert!(intercept.abs() < 1e-6);
        assert!((r_squared - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_regression_errors() {
        let x = vec![1.0, 1.0, 1.0];
        let y = vec![2.0, 3.0, 4.0];
        assert!(matches!(
            linear_regression(&x, &y),
            Err(StatsError::NoVariance)
        ));

        let x2 = vec![1.0, 2.0];
        let y2 = vec![1.0];
        assert!(matches!(
            linear_regression(&x2, &y2),
            Err(StatsError::LengthMismatch { .. })
        ));
    }
}
