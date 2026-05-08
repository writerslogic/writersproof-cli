// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared statistical utility functions for distribution types.

/// Pearson autocorrelation of a time series at the given lag.
/// Returns 0.0 if the series is too short or has zero variance.
pub(super) fn pearson_autocorrelation(series: &[f64], lag: usize) -> f64 {
    if series.len() <= lag {
        return 0.0;
    }
    let n = series.len() - lag;
    let mean_x: f64 = series[..n].iter().sum::<f64>() / n as f64;
    let mean_y: f64 = series[lag..].iter().sum::<f64>() / n as f64;

    let mut cov = 0.0f64;
    let mut var_x = 0.0f64;
    let mut var_y = 0.0f64;
    for i in 0..n {
        let dx = series[i] - mean_x;
        let dy = series[i + lag] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    let denom = (var_x * var_y).sqrt();
    if denom <= 0.0 || !denom.is_finite() {
        return 0.0;
    }
    let r = cov / denom;
    if r.is_finite() { r.clamp(-1.0, 1.0) } else { 0.0 }
}

/// O(n) percentile selection for [5th, 25th, 50th, 75th, 95th].
pub(super) fn compute_percentiles(data: &[f64]) -> [f64; 5] {
    let mut buf = data.to_vec();
    let n = buf.len();
    if n == 0 {
        return [0.0; 5];
    }
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
}
