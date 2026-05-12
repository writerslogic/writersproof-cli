// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Keystroke cadence analysis.

use crate::jitter::SimpleJitterSample;
use crate::utils::stats::{coefficient_of_variation, mean, mean_and_std_dev, median, std_dev};

use super::constants::CORRECTION_ZONE;
use super::types::{CadenceMetrics, ROBOTIC_CV_THRESHOLD};

/// IKI threshold in nanoseconds for fast-burst detection (200 ms).
/// f64 version of constants::BURST_THRESHOLD_NS for direct f64 arithmetic.
const BURST_THRESHOLD_NS_F64: f64 = 200_000_000.0;

/// IKI threshold in nanoseconds for pause detection (2 seconds).
/// f64 version of constants::PAUSE_THRESHOLD_NS for direct f64 arithmetic.
const PAUSE_THRESHOLD_NS_F64: f64 = 2_000_000_000.0;

/// IKI threshold in nanoseconds for cognitive pause detection (1 second).
const COGNITIVE_PAUSE_THRESHOLD_NS: f64 = 1_000_000_000.0;

/// Sentence-level pause upper bound (3 seconds).
const SENTENCE_PAUSE_UPPER_NS: f64 = 3_000_000_000.0;

/// Paragraph-level pause upper bound (10 seconds).
const PARAGRAPH_PAUSE_UPPER_NS: f64 = 10_000_000_000.0;

/// Number of post-pause keystrokes to analyze.
const POST_PAUSE_WINDOW: usize = 5;

/// Minimum consecutive fast keystrokes to qualify as a burst.
const MIN_BURST_LENGTH: usize = 3;

/// Minimum samples needed before flagging content as retyped.
const MIN_RETYPED_SAMPLES: usize = 20;

/// Analyze keystroke cadence from jitter samples.
pub fn analyze_cadence(samples: &[SimpleJitterSample]) -> CadenceMetrics {
    let mut metrics = CadenceMetrics::default();

    if samples.len() < 2 {
        return metrics;
    }

    let ikis: Vec<f64> = samples
        .windows(2)
        .map(|w| (w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns)).max(0) as f64)
        .collect();

    if ikis.is_empty() {
        return metrics;
    }

    metrics.mean_iki_ns = mean(&ikis);
    metrics.std_dev_iki_ns = std_dev(&ikis);
    metrics.coefficient_of_variation = coefficient_of_variation(&ikis);
    metrics.median_iki_ns = median(&ikis);

    metrics.is_robotic = metrics.coefficient_of_variation < ROBOTIC_CV_THRESHOLD;

    let (bursts, pauses) = detect_bursts_and_pauses(&ikis);
    metrics.burst_count = bursts.len();
    metrics.pause_count = pauses.len();

    if !bursts.is_empty() {
        metrics.avg_burst_length =
            bursts.iter().map(|b| b.length as f64).sum::<f64>() / bursts.len() as f64;
    }

    if !pauses.is_empty() {
        metrics.avg_pause_duration_ns = pauses.iter().sum::<f64>() / pauses.len() as f64;
    }

    metrics.percentiles = if ikis.len() < 5 {
        // Too few samples for meaningful percentile estimation; rounding
        // errors in index calculation can select the wrong element.
        [0.0; 5]
    } else {
        // Use select_nth_unstable for O(n) percentile extraction instead of
        // cloning and sorting the full Vec.
        let mut buf = ikis.clone();
        let len = buf.len();
        let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
        let pct_idx = |p: usize| -> usize {
            ((p as f64 / 100.0 * (len - 1) as f64).round() as usize).min(len - 1)
        };
        let indices = [
            pct_idx(10),
            pct_idx(25),
            pct_idx(50),
            pct_idx(75),
            pct_idx(90),
        ];
        // Extract percentiles from largest to smallest index so each
        // select_nth_unstable operates on the remaining unsorted tail.
        let mut result = [0.0f64; 5];
        let mut sorted_indices: Vec<(usize, usize)> = indices.iter().copied().enumerate().collect();
        sorted_indices.sort_by(|a, b| b.1.cmp(&a.1));
        for (orig_pos, idx) in sorted_indices {
            buf.select_nth_unstable_by(idx, cmp);
            result[orig_pos] = buf[idx];
        }
        result
    };

    metrics.cross_hand_timing_ratio = compute_cross_hand_timing_ratio(samples, &ikis);
    metrics.post_pause_cv = compute_post_pause_cv(&ikis);
    metrics.iki_autocorrelation = compute_iki_autocorrelation(&ikis);
    metrics.correction_ratio = crate::utils::Probability::clamp(compute_correction_ratio(samples));
    metrics.pause_depth_distribution = compute_pause_depth_distribution(&ikis);
    metrics.burst_speed_cv = compute_burst_speed_cv(&bursts, &ikis);
    metrics.zero_variance_windows = count_zero_variance_windows(&ikis);

    metrics.structural_homogeneity_score = Some(compute_structural_homogeneity_score(&ikis));
    metrics.planning_pause_rate = compute_planning_pause_rate(&ikis);

    // Sanitize non-finite values from ratio/CV computations
    if !metrics.coefficient_of_variation.is_finite() {
        metrics.coefficient_of_variation = 0.0;
    }
    if !metrics.cross_hand_timing_ratio.is_finite() {
        metrics.cross_hand_timing_ratio = 0.0;
    }
    if !metrics.post_pause_cv.is_finite() {
        metrics.post_pause_cv = 0.0;
    }
    if !metrics.iki_autocorrelation.is_finite() {
        metrics.iki_autocorrelation = 0.0;
    }
    if !metrics.correction_ratio.is_finite() {
        metrics.correction_ratio = crate::utils::Probability::ZERO;
    }
    if !metrics.burst_speed_cv.is_finite() {
        metrics.burst_speed_cv = 0.0;
    }

    // Dwell time (key hold duration) analysis
    let dwell_times: Vec<f64> = samples
        .iter()
        .filter_map(|s| s.dwell_time_ns.map(|d| d as f64))
        .collect();
    if dwell_times.len() >= 5 {
        let (mean, std) = mean_and_std_dev(&dwell_times);
        metrics.mean_dwell_ns = mean;
        if mean > f64::EPSILON {
            metrics.dwell_cv = crate::utils::finite_or(std / mean, 0.0);
        }
    }

    // Flight time (release-to-press gap) analysis
    let flight_times: Vec<f64> = samples
        .iter()
        .filter_map(|s| s.flight_time_ns.map(|f| f as f64))
        .collect();
    if flight_times.len() >= 5 {
        let (mean, std) = mean_and_std_dev(&flight_times);
        metrics.mean_flight_ns = mean;
        if mean > f64::EPSILON {
            metrics.flight_cv = crate::utils::finite_or(std / mean, 0.0);
        }
    }

    metrics
}

/// Compute ratio of cross-hand IKI std_dev to same-hand IKI std_dev.
///
/// Zones 0-3 are left hand, 4-7 are right hand. Cross-hand transitions
/// naturally have more timing variance than same-hand transitions in
/// cognitive writing. Transcriptive typing shows less differentiation.
fn compute_cross_hand_timing_ratio(samples: &[SimpleJitterSample], ikis: &[f64]) -> f64 {
    let mut cross_hand_ikis = Vec::new();
    let mut same_hand_ikis = Vec::new();

    for (i, iki) in ikis.iter().enumerate() {
        let from_zone = samples[i].zone;
        let to_zone = samples[i + 1].zone;
        // Skip unmapped zones.
        if from_zone == CORRECTION_ZONE || to_zone == CORRECTION_ZONE {
            continue;
        }
        let from_left = from_zone < 4;
        let to_left = to_zone < 4;
        if from_left == to_left {
            same_hand_ikis.push(*iki);
        } else {
            cross_hand_ikis.push(*iki);
        }
    }

    let cross_std = std_dev(&cross_hand_ikis);
    let same_std = std_dev(&same_hand_ikis);

    if same_std > 0.0 {
        cross_std / same_std
    } else {
        0.0
    }
}

/// Compute CV of the first N keystrokes after each cognitive pause (>1s).
///
/// In cognitive writing, the burst after a thinking pause has variable speed
/// as the writer translates thoughts to keystrokes. Transcriptive typing
/// resumes at a uniform pace.
fn compute_post_pause_cv(ikis: &[f64]) -> f64 {
    let mut post_pause_ikis = Vec::new();

    let mut i = 0;
    while i < ikis.len() {
        if ikis[i] > COGNITIVE_PAUSE_THRESHOLD_NS {
            let window_end = (i + 1 + POST_PAUSE_WINDOW).min(ikis.len());
            let window = &ikis[i + 1..window_end];
            if window.len() >= 2 {
                post_pause_ikis.extend_from_slice(window);
            }
        }
        i += 1;
    }

    if post_pause_ikis.len() < 2 {
        return 0.0;
    }

    coefficient_of_variation(&post_pause_ikis)
}

/// Compute lag-1 autocorrelation of the IKI sequence.
///
/// Cognitive writing produces near-zero autocorrelation (each interval is
/// roughly independent). Transcriptive typing produces positive autocorrelation
/// because the rhythm is consistently maintained.
fn compute_iki_autocorrelation(ikis: &[f64]) -> f64 {
    if ikis.len() < 3 {
        return 0.0;
    }

    let n = ikis.len();
    let (mean, variance) = crate::utils::stats::mean_and_sample_variance(ikis);

    if variance <= 0.0 {
        return 0.0;
    }

    let covariance: f64 = ikis
        .windows(2)
        .map(|w| (w[0] - mean) * (w[1] - mean))
        .sum::<f64>()
        / (n - 1) as f64;

    (covariance / variance).clamp(-1.0, 1.0)
}

/// Compute fraction of keystrokes tagged as corrections (backspace/delete).
///
/// The zone field is set to `CORRECTION_ZONE` (0xFF) for unmapped keys,
/// which includes backspace and delete. Cognitive writing has more corrections
/// (>0.05) while transcriptive typing has almost none (<0.02).
fn compute_correction_ratio(samples: &[SimpleJitterSample]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let corrections = samples.iter().filter(|s| s.zone == CORRECTION_ZONE).count();
    corrections as f64 / samples.len() as f64
}

/// Classify pauses into duration tiers and return normalized distribution.
///
/// Tiers: sentence-level (1-3s), paragraph-level (3-10s), deep thought (>10s).
/// Cognitive writing shows a spread across all tiers; transcriptive typing
/// concentrates pauses in the sentence tier or has none at all.
fn compute_pause_depth_distribution(ikis: &[f64]) -> [f64; 3] {
    let mut counts = [0u64; 3];

    for &iki in ikis {
        if iki > COGNITIVE_PAUSE_THRESHOLD_NS && iki <= SENTENCE_PAUSE_UPPER_NS {
            counts[0] += 1;
        } else if iki > SENTENCE_PAUSE_UPPER_NS && iki <= PARAGRAPH_PAUSE_UPPER_NS {
            counts[1] += 1;
        } else if iki > PARAGRAPH_PAUSE_UPPER_NS {
            counts[2] += 1;
        }
    }

    let total: u64 = counts.iter().sum();
    if total == 0 {
        return [0.0; 3];
    }
    [
        counts[0] as f64 / total as f64,
        counts[1] as f64 / total as f64,
        counts[2] as f64 / total as f64,
    ]
}

/// Contiguous run of fast keystrokes.
#[derive(Debug, Clone)]
pub struct TypingBurst {
    /// Index into the IKI array where this burst begins.
    pub start_idx: usize,
    /// Number of consecutive fast keystrokes in this burst.
    pub length: usize,
    /// Mean inter-key interval within this burst (nanoseconds).
    pub avg_iki_ns: f64,
}

/// Segment IKI sequence into bursts and pauses.
fn detect_bursts_and_pauses(ikis: &[f64]) -> (Vec<TypingBurst>, Vec<f64>) {
    let mut bursts = Vec::new();
    let mut pauses = Vec::new();

    let mut burst_start: Option<usize> = None;
    let mut burst_sum = 0.0;

    for (i, &iki) in ikis.iter().enumerate() {
        if iki < BURST_THRESHOLD_NS_F64 {
            if burst_start.is_none() {
                burst_start = Some(i);
                burst_sum = 0.0;
            }
            burst_sum += iki;
        } else {
            if let Some(start) = burst_start {
                let length = i - start;
                if length >= MIN_BURST_LENGTH {
                    bursts.push(TypingBurst {
                        start_idx: start,
                        length,
                        avg_iki_ns: burst_sum / length as f64,
                    });
                }
                burst_start = None;
            }

            if iki > PAUSE_THRESHOLD_NS_F64 {
                pauses.push(iki);
            }
        }
    }

    if let Some(start) = burst_start {
        let length = ikis.len() - start;
        if length >= MIN_BURST_LENGTH {
            bursts.push(TypingBurst {
                start_idx: start,
                length,
                avg_iki_ns: burst_sum / length as f64,
            });
        }
    }

    (bursts, pauses)
}

/// Return `true` if cadence is too rhythmic for original composition (likely retyped).
pub fn is_retyped_content(samples: &[SimpleJitterSample]) -> bool {
    samples.len() >= MIN_RETYPED_SAMPLES && analyze_cadence(samples).is_robotic
}

/// Average CV of typing speed within individual bursts.
/// Cognitive writing shows natural speed variation within each burst (CV >0.25).
/// Transcriptive typing maintains constant speed within bursts (CV <0.15).
fn compute_burst_speed_cv(bursts: &[TypingBurst], ikis: &[f64]) -> f64 {
    let valid_bursts: Vec<f64> = bursts
        .iter()
        .filter(|b| b.length >= MIN_BURST_LENGTH)
        .filter_map(|b| {
            let end = (b.start_idx + b.length).min(ikis.len());
            let burst_ikis = &ikis[b.start_idx..end];
            if burst_ikis.len() < 3 {
                return None;
            }
            Some(coefficient_of_variation(burst_ikis))
        })
        .collect();

    if valid_bursts.is_empty() {
        return 0.0;
    }
    mean(&valid_bursts)
}

/// Compute the CV of inter-pause-gap lengths (gaps between consecutive pauses > 2s).
///
/// AI-transcribed text produces abnormally uniform inter-pause gaps (CV < 0.15).
/// Genuine cognitive writing has highly variable gaps because the writer pauses at
/// irregular points to think. Returns the CV, or `None` when fewer than 3 pauses exist.
pub fn compute_structural_homogeneity_score(ikis: &[f64]) -> f64 {
    let pause_positions: Vec<f64> = ikis
        .iter()
        .enumerate()
        .filter(|(_, &iki)| iki > PAUSE_THRESHOLD_NS_F64)
        .map(|(i, _)| i as f64)
        .collect();

    let gaps: Vec<f64> = pause_positions.windows(2).map(|w| w[1] - w[0]).collect();

    if gaps.len() < 3 {
        return 0.5;
    }

    coefficient_of_variation(&gaps)
}

/// Count 500ms sliding windows where IKI variance is near zero (<5ms std dev).
/// Any window with effectively zero timing variation is suspicious; >3 windows
/// strongly suggests transcription or automated input.
fn count_zero_variance_windows(ikis: &[f64]) -> usize {
    /// Std dev threshold below which a window is considered zero-variance (5ms).
    const ZERO_VAR_THRESHOLD_NS: f64 = 5_000_000.0;
    /// Approximate number of IKIs in a 500ms window at typical typing speed.
    const WINDOW_SIZE: usize = 5;

    if ikis.len() < WINDOW_SIZE {
        return 0;
    }

    let mut count = 0;
    for window in ikis.windows(WINDOW_SIZE) {
        let (mean, variance) = crate::utils::stats::mean_and_variance(window);
        if mean <= 0.0 {
            continue;
        }
        if variance.sqrt() < ZERO_VAR_THRESHOLD_NS {
            count += 1;
        }
    }
    count
}

/// Fraction of keystrokes preceded by a planning pause (>2s).
///
/// Composition produces ~2x the planning pause rate of transcription
/// (diary calibration: 0.062 composing vs 0.007-0.009 transcribing).
fn compute_planning_pause_rate(ikis: &[f64]) -> Option<f64> {
    if ikis.len() < 10 {
        return None;
    }
    let pauses = ikis.iter().filter(|&&iki| iki > PAUSE_THRESHOLD_NS_F64).count();
    Some(pauses as f64 / (ikis.len() + 1) as f64)
}
