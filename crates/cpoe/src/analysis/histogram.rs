// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Reusable histogram builders for binning and entropy computation.
//!
//! Replaces ad-hoc histogram construction scattered across forensics,
//! evidence export, and fingerprint modules.

/// Bin a value into edge-based bins.
///
/// Returns the index of the last edge that `value >= edge`. This matches
/// the `rposition` pattern used throughout the codebase.
///
/// # Panics
/// Panics if `edges` is empty.
#[inline]
pub fn bin_by_edges(value: u64, edges: &[u64]) -> usize {
    edges.iter().rposition(|&edge| value >= edge).unwrap_or(0)
}

/// Bin a normalized value (0.0..1.0) into `num_bins` equal-width bins.
#[inline]
pub fn bin_linear_normalized(value: f64, num_bins: usize) -> usize {
    let clamped = value.clamp(0.0, 0.9999);
    let idx = (clamped * num_bins as f64).floor() as usize;
    idx.min(num_bins - 1)
}

/// Build a histogram from values using edge-based binning.
///
/// Each value is placed in the bin corresponding to the last edge it exceeds.
/// The returned array has `num_bins` elements.
pub fn edge_histogram(values: &[u64], edges: &[u64], num_bins: usize) -> Vec<u64> {
    let mut bins = vec![0u64; num_bins];
    for &v in values {
        let bin = bin_by_edges(v, edges);
        bins[bin.min(num_bins - 1)] += 1;
    }
    bins
}

/// Shannon entropy of a histogram (in bits).
///
/// `H = -sum(p_i * log2(p_i))` where `p_i = count_i / total`.
pub fn shannon_entropy_usize(histogram: &[usize]) -> f64 {
    let n: usize = histogram.iter().sum();
    if n == 0 {
        return 0.0;
    }
    let n_f = n as f64;
    let mut entropy = 0.0;
    for &count in histogram {
        if count > 0 {
            let p = count as f64 / n_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Shannon entropy of a histogram with u64 counts (in bits).
pub fn shannon_entropy_u64(histogram: &[u64]) -> f64 {
    let n: u64 = histogram.iter().sum();
    if n == 0 {
        return 0.0;
    }
    let n_f = n as f64;
    let mut entropy = 0.0;
    for &count in histogram {
        if count > 0 {
            let p = count as f64 / n_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Shannon entropy in centibits (1 bit = 100 centibits), rounded.
pub fn shannon_entropy_centibits(histogram: &[u64]) -> u64 {
    (shannon_entropy_u64(histogram) * 100.0).round() as u64
}

/// Normalize a histogram in place so entries sum to 1.0.
pub fn normalize(hist: &mut [f64]) {
    let total: f64 = hist.iter().sum();
    if total > 0.0 {
        for h in hist {
            *h /= total;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bin_by_edges() {
        let edges = [0u64, 50, 100, 200, 500];
        assert_eq!(bin_by_edges(0, &edges), 0);
        assert_eq!(bin_by_edges(49, &edges), 0);
        assert_eq!(bin_by_edges(50, &edges), 1);
        assert_eq!(bin_by_edges(100, &edges), 2);
        assert_eq!(bin_by_edges(999, &edges), 4);
    }

    #[test]
    fn test_bin_linear_normalized() {
        assert_eq!(bin_linear_normalized(0.0, 8), 0);
        assert_eq!(bin_linear_normalized(0.5, 8), 4);
        assert_eq!(bin_linear_normalized(0.999, 8), 7);
        assert_eq!(bin_linear_normalized(1.0, 8), 7); // clamped
        assert_eq!(bin_linear_normalized(-0.1, 8), 0); // clamped
    }

    #[test]
    fn test_edge_histogram() {
        let edges = [0u64, 100, 500];
        let values = vec![50, 150, 200, 600, 10];
        let hist = edge_histogram(&values, &edges, 3);
        assert_eq!(hist, vec![2, 2, 1]);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // 4 bins with equal counts → log2(4) = 2.0 bits
        let hist = [10usize, 10, 10, 10];
        let e = shannon_entropy_usize(&hist);
        assert!((e - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_shannon_entropy_single_bin() {
        let hist = [100usize, 0, 0, 0];
        let e = shannon_entropy_usize(&hist);
        assert!((e - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        let hist: [usize; 0] = [];
        assert_eq!(shannon_entropy_usize(&hist), 0.0);
    }

    #[test]
    fn test_normalize() {
        let mut hist = [2.0, 3.0, 5.0];
        normalize(&mut hist);
        assert!((hist[0] - 0.2).abs() < 1e-10);
        assert!((hist[1] - 0.3).abs() < 1e-10);
        assert!((hist[2] - 0.5).abs() < 1e-10);
    }
}
