// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Edit topology analysis functions.

use std::collections::HashMap;

use super::error::ForensicsError;
use super::types::{
    PrimaryMetrics, RegionData, SortedEvents, DEFAULT_APPEND_THRESHOLD, DEFAULT_HISTOGRAM_BINS,
    MIN_EVENTS_FOR_ANALYSIS,
};

/// Compute all primary metrics from events and edit regions.
pub fn compute_primary_metrics(
    sorted: SortedEvents<'_>,
    regions: &HashMap<i64, Vec<RegionData>>,
) -> Result<PrimaryMetrics, ForensicsError> {
    if sorted.len() < MIN_EVENTS_FOR_ANALYSIS {
        return Err(ForensicsError::InsufficientData);
    }

    let all_regions = flatten_regions(regions);
    if all_regions.is_empty() {
        return Err(ForensicsError::InsufficientData);
    }

    let mut pm = PrimaryMetrics {
        monotonic_append_ratio: crate::utils::Probability::clamp(monotonic_append_ratio(
            &all_regions,
            DEFAULT_APPEND_THRESHOLD,
        )),
        edit_entropy: edit_entropy(&all_regions, DEFAULT_HISTOGRAM_BINS),
        median_interval: median_interval(sorted),
        positive_negative_ratio: crate::utils::Probability::clamp(positive_negative_ratio(
            &all_regions,
        )),
        deletion_clustering: deletion_clustering_coef(&all_regions),
        ..Default::default()
    };

    // Sanitize non-finite values and log when clamping occurs.
    if !pm.monotonic_append_ratio.is_finite() {
        log::warn!(
            "topology: monotonic_append_ratio non-finite ({}), using 0.0",
            pm.monotonic_append_ratio.get()
        );
        pm.monotonic_append_ratio = crate::utils::Probability::ZERO;
    }
    if !pm.edit_entropy.is_finite() {
        log::warn!(
            "topology: edit_entropy non-finite ({}), using 0.0",
            pm.edit_entropy
        );
        pm.edit_entropy = 0.0;
    }
    if !pm.median_interval.is_finite() {
        log::warn!(
            "topology: median_interval non-finite ({}), using 0.0",
            pm.median_interval
        );
        pm.median_interval = 0.0;
    }
    if !pm.positive_negative_ratio.is_finite() {
        log::warn!(
            "topology: positive_negative_ratio non-finite ({}), using 0.5",
            pm.positive_negative_ratio.get()
        );
        pm.positive_negative_ratio = crate::utils::Probability::clamp(0.5);
    }
    if !pm.deletion_clustering.is_finite() {
        log::warn!(
            "topology: deletion_clustering non-finite ({}), using 0.0",
            pm.deletion_clustering
        );
        pm.deletion_clustering = 0.0;
    }

    Ok(pm)
}

/// Fraction of edits at document end: `|{r : r.start_pct >= threshold}| / |R|`
pub fn monotonic_append_ratio(regions: &[RegionData], threshold: f32) -> f64 {
    if regions.is_empty() {
        return 0.0;
    }

    let append_count = regions.iter().filter(|r| r.start_pct >= threshold).count();
    append_count as f64 / regions.len() as f64
}

/// Shannon entropy of edit position histogram: `H = -sum (c_j/n) * log2(c_j/n)`
pub fn edit_entropy(regions: &[RegionData], bins: usize) -> f64 {
    if regions.is_empty() || bins == 0 {
        return 0.0;
    }

    let mut histogram = vec![0usize; bins];
    for r in regions {
        // Keep f32 arithmetic to match input precision of start_pct: f32.
        let pos = r.start_pct.clamp(0.0, 0.9999);
        let bin_idx = ((pos * bins as f32) as usize).min(bins - 1);
        histogram[bin_idx] += 1;
    }

    shannon_entropy(&histogram)
}

/// Shannon entropy from a frequency histogram.
pub(crate) fn shannon_entropy(histogram: &[usize]) -> f64 {
    crate::analysis::histogram::shannon_entropy_usize(histogram)
}

/// Median inter-event interval in seconds.
pub fn median_interval(sorted: SortedEvents<'_>) -> f64 {
    if sorted.len() < 2 {
        return 0.0;
    }

    let intervals: Vec<f64> = sorted
        .windows(2)
        .map(|w| crate::utils::ns_to_secs(w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns)))
        .filter(|&iv| iv > 0.0)
        .collect();

    compute_median(&intervals)
}

/// O(n) median via `select_nth_unstable_by`.
pub(crate) fn compute_median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut buf = values.to_vec();
    let n = buf.len();
    let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
    if n % 2 == 0 {
        buf.select_nth_unstable_by(n / 2 - 1, cmp);
        let lower = buf[n / 2 - 1];
        buf.select_nth_unstable_by(n / 2, cmp);
        let upper = buf[n / 2];
        (lower + upper) / 2.0
    } else {
        buf.select_nth_unstable_by(n / 2, cmp);
        buf[n / 2]
    }
}

/// Insertion ratio: `|{r : delta_sign > 0}| / |{r : delta_sign != 0}|`
pub fn positive_negative_ratio(regions: &[RegionData]) -> f64 {
    let mut insertions = 0;
    let mut total = 0;

    for r in regions {
        if r.delta_sign > 0 {
            insertions += 1;
            total += 1;
        } else if r.delta_sign < 0 {
            total += 1;
        }
        // delta_sign == 0 (replacements) excluded
    }

    if total == 0 {
        return 0.5;
    }

    insertions as f64 / total as f64
}

/// Compute mean nearest-neighbor distance among deletion positions, normalized
/// against the expected uniform spacing `1/(n+1)`.
///
/// < 1 = clustered (revision pass), ~ 1 = scattered (suspicious), 0 = no deletions.
pub fn deletion_clustering_coef(regions: &[RegionData]) -> f64 {
    let mut deletion_positions: Vec<f64> = regions
        .iter()
        .filter(|r| r.delta_sign < 0)
        .map(|r| r.start_pct as f64)
        .collect();

    let n = deletion_positions.len();
    if n < 2 {
        return 0.0;
    }

    deletion_positions.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mut total_dist = 0.0;
    for i in 0..n {
        let mut min_dist = f64::MAX;

        if i > 0 {
            let dist = deletion_positions[i] - deletion_positions[i - 1];
            if dist < min_dist {
                min_dist = dist;
            }
        }

        if i < n - 1 {
            let dist = deletion_positions[i + 1] - deletion_positions[i];
            if dist < min_dist {
                min_dist = dist;
            }
        }

        total_dist += min_dist;
    }

    let mean_dist = total_dist / n as f64;

    // Expected nearest-neighbor distance for n uniform points in [0,1]
    let expected_uniform_dist = 1.0 / (n + 1) as f64;

    if expected_uniform_dist == 0.0 {
        return 0.0;
    }

    mean_dist / expected_uniform_dist
}

/// Flatten all regions into a single `Vec`.
fn flatten_regions(regions: &HashMap<i64, Vec<RegionData>>) -> Vec<RegionData> {
    regions.values().flat_map(|rs| rs.iter().cloned()).collect()
}
