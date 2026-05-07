// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub(crate) const MAX_JITTER_BATCHES_PER_WINDOW: u64 = 50;
/// Refill rate: 10 batches/sec = 10 milli-tokens per millisecond.
pub(crate) const JITTER_REFILL_PER_MS: u64 = 10;
/// One batch costs 1000 milli-tokens; max bucket = 50 * 1000.
pub(crate) const JITTER_TOKEN_COST: u64 = 1_000;
pub(crate) const JITTER_TOKEN_MAX: u64 = MAX_JITTER_BATCHES_PER_WINDOW * JITTER_TOKEN_COST;
pub(crate) const MAX_BATCH_SIZE: usize = 200;

pub(crate) struct JitterStats {
    pub(crate) count: usize,
    pub(crate) mean: f64,
    pub(crate) std_dev: f64,
    pub(crate) min: u64,
    pub(crate) max: u64,
}

pub(crate) fn compute_jitter_stats(intervals: &[u64]) -> JitterStats {
    if intervals.is_empty() {
        return JitterStats {
            count: 0,
            mean: 0.0,
            std_dev: 0.0,
            min: 0,
            max: 0,
        };
    }
    let count = intervals.len();
    let sum: u64 = intervals
        .iter()
        .copied()
        .fold(0u64, |a, b| a.saturating_add(b));
    let mean = sum as f64 / count as f64;

    let variance = intervals
        .iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / count as f64;

    JitterStats {
        count,
        mean,
        std_dev: variance.sqrt(),
        min: intervals.iter().copied().min().unwrap_or(0),
        max: intervals.iter().copied().max().unwrap_or(0),
    }
}

/// Minimum sample count to produce a meaningful forensic verdict.
const MIN_FORENSIC_SAMPLES: usize = 20;
/// CV threshold below which typing is suspiciously machine-regular.
const SYNTHETIC_CV_THRESHOLD: f64 = 0.08;
/// Fraction of intervals that are multiples of 10ms (10_000µs) indicating
/// rounded/synthetic generation.
const ROUNDING_RATIO_THRESHOLD: f64 = 0.60;
/// Fraction of intervals within ±5% of the mean indicating piston-like regularity.
const REGULARITY_RATIO_THRESHOLD: f64 = 0.70;

pub(crate) struct BrowserJitterForensics {
    pub(crate) sample_count: usize,
    /// Coefficient of variation (std_dev / mean). Low values indicate machine regularity.
    pub(crate) cv: f64,
    /// Fraction of intervals within ±5% of the mean.
    pub(crate) regularity_ratio: f64,
    /// Fraction of intervals that are exact multiples of 10_000µs (10ms).
    pub(crate) rounding_ratio: f64,
    /// Human-plausible verdict.
    pub(crate) verdict: &'static str,
}

/// Run forensic analysis on accumulated browser keystroke intervals.
///
/// Intervals are in microseconds (validated 10_000..=10_000_000 by the caller).
/// Returns `None` when there are fewer than `MIN_FORENSIC_SAMPLES` intervals.
pub(crate) fn analyze_browser_jitter(intervals: &[u64]) -> Option<BrowserJitterForensics> {
    if intervals.len() < MIN_FORENSIC_SAMPLES {
        return None;
    }

    let stats = compute_jitter_stats(intervals);
    if stats.mean == 0.0 {
        return None;
    }

    let cv = stats.std_dev / stats.mean;

    let within_5pct = intervals
        .iter()
        .filter(|&&v| {
            let delta = if v as f64 > stats.mean {
                v as f64 - stats.mean
            } else {
                stats.mean - v as f64
            };
            delta / stats.mean <= 0.05
        })
        .count();
    let regularity_ratio = within_5pct as f64 / intervals.len() as f64;

    // 10ms = 10_000µs; check for multiples of 10_000
    let rounded = intervals
        .iter()
        .filter(|&&v| v % 10_000 == 0)
        .count();
    let rounding_ratio = rounded as f64 / intervals.len() as f64;

    let verdict = if cv < SYNTHETIC_CV_THRESHOLD
        || regularity_ratio > REGULARITY_RATIO_THRESHOLD
        || rounding_ratio > ROUNDING_RATIO_THRESHOLD
    {
        "synthetic_suspect"
    } else if cv < 0.20 || regularity_ratio > 0.50 {
        "low_variance"
    } else {
        "human_plausible"
    };

    Some(BrowserJitterForensics {
        sample_count: intervals.len(),
        cv,
        regularity_ratio,
        rounding_ratio,
        verdict,
    })
}
