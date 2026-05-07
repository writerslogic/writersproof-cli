// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared math and statistics utilities.

use crate::utils::finite_or;

/// Compute the arithmetic mean of a slice of `f64`.
pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let sum: f64 = values.iter().sum();
    sum / values.len() as f64
}

/// Compute population mean and variance in a single pass using Welford's algorithm.
/// Returns (mean, variance). Numerically stable for large values and small deviations.
pub fn mean_and_variance(values: &[f64]) -> (f64, f64) {
    let n = values.len();
    if n == 0 {
        return (0.0, 0.0);
    }
    if n == 1 {
        return (values[0], 0.0);
    }

    // Welford's algorithm for numerical stability
    let mut m = 0.0;
    let mut s = 0.0;
    for (k, &x) in values.iter().enumerate() {
        let old_m = m;
        m += (x - old_m) / (k + 1) as f64;
        s += (x - old_m) * (x - m);
    }

    (m, s / n as f64)
}

/// Compute sample mean and variance (Bessel-corrected, N-1 denominator) in a single pass.
/// Returns (mean, sample_variance). Use this when the input is a sample from a larger population.
pub fn mean_and_sample_variance(values: &[f64]) -> (f64, f64) {
    let n = values.len();
    if n < 2 {
        return (if n == 1 { values[0] } else { 0.0 }, 0.0);
    }

    // Welford's algorithm for numerical stability
    let mut m = 0.0;
    let mut s = 0.0;
    for (k, &x) in values.iter().enumerate() {
        let old_m = m;
        m += (x - old_m) / (k + 1) as f64;
        s += (x - old_m) * (x - m);
    }

    (m, s / (n - 1) as f64)
}

/// Compute population standard deviation and mean in a single pass.
/// Returns (mean, std_dev).
pub fn mean_and_std_dev(values: &[f64]) -> (f64, f64) {
    let (m, var) = mean_and_variance(values);
    (m, var.sqrt())
}

/// Compute sample standard deviation and mean in a single pass (Bessel-corrected, N-1).
/// Returns (mean, sample_std_dev).
pub fn mean_and_sample_std_dev(values: &[f64]) -> (f64, f64) {
    let (m, var) = mean_and_sample_variance(values);
    (m, var.sqrt())
}

/// Compute the population standard deviation of a slice of `f64`.
pub fn std_dev(values: &[f64]) -> f64 {
    mean_and_std_dev(values).1
}

/// Compute the coefficient of variation (std_dev / mean) of a slice of `f64`.
pub fn coefficient_of_variation(values: &[f64]) -> f64 {
    let (m, std) = mean_and_std_dev(values);
    if m.abs() <= f64::EPSILON {
        return 0.0;
    }
    finite_or(std / m, 0.0)
}

/// Map `value` from the range `[low, high]` to `[0.0, 1.0]`, clamped at both ends.
///
/// Returns `0.0` for non-finite inputs or degenerate ranges (`high ≈ low`).
pub fn lerp_score(value: f64, low: f64, high: f64) -> f64 {
    if !value.is_finite() || (high - low).abs() < f64::EPSILON {
        return 0.0;
    }
    crate::utils::Probability::clamp((value - low) / (high - low)).get()
}

/// Compute sample mean and standard deviation of a `f32` slice.
///
/// Converts to `f64` internally for numerical stability, then narrows back.
/// Returns `(0.0, 0.0)` for empty slices; `(values[0], 0.0)` for single-element slices.
/// Uses Bessel-corrected (N-1) denominator — appropriate for a sample of confidence scores.
pub fn mean_and_std_dev_f32(values: &[f32]) -> (f32, f32) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let f64_values: Vec<f64> = values.iter().map(|&v| v as f64).collect();
    let (m, sd) = mean_and_sample_std_dev(&f64_values);
    (m as f32, sd as f32)
}

/// Compute the median of a slice of `f64`.
pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let len = sorted.len();
    if len % 2 == 1 {
        sorted[len / 2]
    } else {
        (sorted[len / 2 - 1] + sorted[len / 2]) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-9;

    #[test]
    fn mean_handles_empty_and_single() {
        assert_eq!(mean(&[]), 0.0);
        assert_eq!(mean(&[42.0]), 42.0);
    }

    #[test]
    fn mean_and_variance_population() {
        // deviations: -2,0,2,-2,2 → squared sum = 16 → pop var = 16/5 = 3.2
        let data = [3.0, 5.0, 7.0, 3.0, 7.0];
        let (m, var) = mean_and_variance(&data);
        assert!((m - 5.0).abs() < EPS);
        assert!((var - 3.2).abs() < EPS);
    }

    #[test]
    fn mean_and_sample_variance_bessel_correction() {
        // Same data; sample variance = 16/(N-1) = 16/4 = 4.0
        let data = [3.0, 5.0, 7.0, 3.0, 7.0];
        let (m, var) = mean_and_sample_variance(&data);
        assert!((m - 5.0).abs() < EPS);
        assert!((var - 4.0).abs() < EPS);
    }

    #[test]
    fn mean_and_sample_std_dev_classic() {
        // Wikipedia's sample: {2,4,4,4,5,5,7,9} → mean=5, sample std ≈ 2.13809
        let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let (m, std) = mean_and_sample_std_dev(&data);
        assert!((m - 5.0).abs() < EPS);
        assert!((std - 2.138089935299395).abs() < 1e-6);
    }

    #[test]
    fn variance_handles_degenerate_inputs() {
        assert_eq!(mean_and_variance(&[]), (0.0, 0.0));
        assert_eq!(mean_and_variance(&[7.0]), (7.0, 0.0));
        assert_eq!(mean_and_sample_variance(&[]), (0.0, 0.0));
        assert_eq!(mean_and_sample_variance(&[7.0]), (7.0, 0.0));
    }

    #[test]
    fn variance_constant_data_is_zero() {
        let data = [42.0; 10];
        assert_eq!(mean_and_variance(&data), (42.0, 0.0));
        assert_eq!(mean_and_sample_variance(&data), (42.0, 0.0));
    }

    #[test]
    fn median_total_cmp_nan_sorted_last() {
        // NaN must sort after all finite values (total_cmp puts NaN at the end).
        let mut data = [f64::NAN, 1.0, 3.0, 2.0];
        data.sort_by(|a, b| a.total_cmp(b));
        assert_eq!(data[0], 1.0);
        assert_eq!(data[1], 2.0);
        assert_eq!(data[2], 3.0);
        assert!(data[3].is_nan());
    }

    #[test]
    fn lerp_score_boundaries() {
        assert_eq!(lerp_score(0.0, 0.0, 1.0), 0.0);
        assert_eq!(lerp_score(0.5, 0.0, 1.0), 0.5);
        assert_eq!(lerp_score(1.0, 0.0, 1.0), 1.0);
        assert_eq!(lerp_score(-1.0, 0.0, 1.0), 0.0); // clamped below
        assert_eq!(lerp_score(2.0, 0.0, 1.0), 1.0); // clamped above
        assert_eq!(lerp_score(f64::NAN, 0.0, 1.0), 0.0);
        assert_eq!(lerp_score(f64::INFINITY, 0.0, 1.0), 0.0);
    }

    #[test]
    fn lerp_score_degenerate_range() {
        // equal low/high — degenerate, return 0.0
        assert_eq!(lerp_score(0.5, 0.5, 0.5), 0.0);
    }

    #[test]
    fn welford_numerical_stability_large_values() {
        // Large magnitudes with small deviations — two-pass loses precision,
        // Welford's stays accurate.
        let base = 1.0e9;
        let data: Vec<f64> = (0..100).map(|i| base + i as f64).collect();
        let (_, var) = mean_and_variance(&data);
        // Variance of 0..99 is 833.25 (population)
        assert!((var - 833.25).abs() < 1e-6);
    }

    #[test]
    fn mean_and_std_dev_f32_empty() {
        assert_eq!(mean_and_std_dev_f32(&[]), (0.0f32, 0.0f32));
    }

    #[test]
    fn mean_and_std_dev_f32_single() {
        let (m, sd) = mean_and_std_dev_f32(&[0.9f32]);
        assert!((m - 0.9f32).abs() < 1e-6);
        assert_eq!(sd, 0.0f32);
    }

    #[test]
    fn mean_and_std_dev_f32_constant() {
        let (m, sd) = mean_and_std_dev_f32(&[0.8f32; 5]);
        assert!((m - 0.8f32).abs() < 1e-6);
        assert!(sd.abs() < 1e-6);
    }

    #[test]
    fn mean_and_std_dev_f32_live_speech_range() {
        // Live speech confidence CV 0.08–0.18; stddev should be detectable.
        let values = [0.82f32, 0.91, 0.78, 0.88, 0.95, 0.80, 0.93];
        let (m, sd) = mean_and_std_dev_f32(&values);
        assert!(m > 0.8 && m < 0.95, "mean {m} out of expected range");
        assert!(sd > 0.04, "stddev {sd} too low for live speech");
    }

    #[test]
    fn mean_and_std_dev_f32_tts_like_uniform() {
        // TTS produces near-identical confidence scores; stddev should be near zero.
        let values = [0.98f32, 0.98, 0.98, 0.99, 0.98];
        let (_, sd) = mean_and_std_dev_f32(&values);
        assert!(sd < 0.01, "stddev {sd} should be near zero for TTS-like input");
    }
}
