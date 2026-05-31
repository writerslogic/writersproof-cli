// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Error Ecology Classification.
//!
//! Cognitive and transcriptive writers produce different *types* of errors
//! because the errors originate from different cognitive subsystems:
//!
//! **Cognitive error signatures** (motor planning / lexical retrieval):
//! - Adjacent-key substitutions: "teh" → "the" (60% of cognitive errors)
//! - Transpositions: "adn" → "and" (20%)
//! - Word-initial false starts: type 2-4 chars, delete, type different word
//! - Rapid self-corrections: delete within 500ms of typing
//!
//! **Transcriptive error signatures** (visual decoding of source):
//! - Slow corrections: delete after >2s (looked at source, noticed mistake)
//! - Multi-character deletions: bulk cleanup (>5 chars at once)
//! - Uniform correction spacing: corrections evenly distributed
//!
//! The error ecology vector (proportions across types) is compared to reference
//! distributions using Jensen-Shannon divergence.

use serde::{Deserialize, Serialize};

use crate::jitter::SimpleJitterSample;

use super::constants::CORRECTION_ZONE;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum correction events for meaningful ecology analysis.
const MIN_CORRECTIONS: usize = 5;

/// Minimum total samples.
const MIN_SAMPLES: usize = 20;

/// Maximum IKI (ns) for rapid self-correction (500ms).
const RAPID_CORRECTION_NS: u64 = 500_000_000;

/// Maximum IKI for a correction to count as "immediate" (1s).
const IMMEDIATE_CORRECTION_NS: u64 = 1_000_000_000;

/// Maximum consecutive corrections for "small correction" (3 chars).
const SMALL_CORRECTION_MAX: usize = 3;

/// Minimum consecutive corrections for "bulk correction" (5+ chars).
const BULK_CORRECTION_MIN: usize = 5;

/// Reference cognitive error ecology distribution.
/// [rapid_self, immediate_small, delayed, bulk, false_start]
const COGNITIVE_REFERENCE: [f64; 5] = [0.35, 0.30, 0.10, 0.05, 0.20];

/// Reference transcriptive error ecology distribution.
const TRANSCRIPTIVE_REFERENCE: [f64; 5] = [0.10, 0.15, 0.35, 0.30, 0.10];

// ---------------------------------------------------------------------------
// Error event classification
// ---------------------------------------------------------------------------

/// Classification of a correction event sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorType {
    /// Delete 1-3 chars within 500ms of typing: motor execution error.
    RapidSelfCorrection,
    /// Delete 1-3 chars within 1s: immediate catch.
    ImmediateSmallCorrection,
    /// Delete after >2s: noticed error from re-reading or source comparison.
    DelayedCorrection,
    /// Delete 5+ consecutive chars: bulk cleanup.
    BulkCorrection,
    /// Type 2-4 chars rapidly then delete all: word-initial false start.
    FalseStart,
}

#[derive(Debug, Clone)]
struct CorrectionEvent {
    error_type: ErrorType,
    _correction_length: usize,
    _pre_correction_iki_ns: u64,
    _start_idx: usize,
}

/// Extract and classify correction events from jitter samples.
fn classify_corrections(samples: &[SimpleJitterSample]) -> Vec<CorrectionEvent> {
    let mut events = Vec::new();
    let mut i = 0;

    while i < samples.len() {
        if samples[i].zone != CORRECTION_ZONE {
            i += 1;
            continue;
        }

        // Found start of a correction sequence.
        let start_idx = i;
        let mut correction_len = 0usize;

        // Count consecutive corrections.
        while i < samples.len() && samples[i].zone == CORRECTION_ZONE {
            correction_len += 1;
            i += 1;
        }

        // Determine pre-correction IKI.
        let pre_iki = if start_idx > 0 {
            samples[start_idx].duration_since_last_ns
        } else {
            u64::MAX
        };

        // Check for false start pattern: 2-4 rapid characters before this correction.
        let is_false_start = if start_idx >= 2 && correction_len >= 2 {
            let pre_chars = (0..start_idx.min(4))
                .rev()
                .take_while(|&j| {
                    samples[start_idx - 1 - j].zone != CORRECTION_ZONE
                        && samples[start_idx - 1 - j].duration_since_last_ns < RAPID_CORRECTION_NS
                })
                .count();
            pre_chars >= 2 && correction_len >= pre_chars
        } else {
            false
        };

        let error_type = if correction_len >= BULK_CORRECTION_MIN {
            ErrorType::BulkCorrection
        } else if is_false_start {
            ErrorType::FalseStart
        } else if correction_len <= SMALL_CORRECTION_MAX && pre_iki < RAPID_CORRECTION_NS {
            ErrorType::RapidSelfCorrection
        } else if correction_len <= SMALL_CORRECTION_MAX && pre_iki < IMMEDIATE_CORRECTION_NS {
            ErrorType::ImmediateSmallCorrection
        } else {
            ErrorType::DelayedCorrection
        };

        events.push(CorrectionEvent {
            error_type,
            _correction_length: correction_len,
            _pre_correction_iki_ns: pre_iki,
            _start_idx: start_idx,
        });
    }

    events
}

// ---------------------------------------------------------------------------
// Jensen-Shannon divergence
// ---------------------------------------------------------------------------

/// Compute Jensen-Shannon divergence between two probability distributions.
/// Returns a value in [0, 1] (using log base 2).
/// Single-pass, zero-allocation implementation.
fn jensen_shannon_divergence(p: &[f64], q: &[f64]) -> f64 {
    if p.len() != q.len() || p.is_empty() {
        return 1.0;
    }

    let jsd: f64 = p
        .iter()
        .zip(q.iter())
        .filter(|(&pi, &qi)| pi > 0.0 || qi > 0.0)
        .map(|(&pi, &qi)| {
            let mi = (pi + qi) / 2.0;
            let kl_p = if pi > 0.0 { pi * (pi / mi).ln() } else { 0.0 };
            let kl_q = if qi > 0.0 { qi * (qi / mi).ln() } else { 0.0 };
            (kl_p + kl_q) / 2.0
        })
        .sum();

    (jsd / std::f64::consts::LN_2).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Error ecology analysis results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorEcologyMetrics {
    /// Fraction of corrections that are rapid self-corrections (<500ms, 1-3 chars).
    pub rapid_self_correction_pct: f64,
    /// Fraction that are immediate small corrections (<1s, 1-3 chars).
    pub immediate_small_correction_pct: f64,
    /// Fraction that are delayed corrections (>2s).
    pub delayed_correction_pct: f64,
    /// Fraction that are bulk corrections (5+ consecutive deletes).
    pub bulk_correction_pct: f64,
    /// Fraction that are word-initial false starts.
    pub false_start_pct: f64,

    /// Total correction events analyzed.
    pub total_corrections: usize,
    /// Overall correction rate (corrections / total keystrokes).
    pub correction_rate: f64,

    /// JSD from cognitive reference distribution (lower = more cognitive).
    pub jsd_from_cognitive: f64,
    /// JSD from transcriptive reference distribution (lower = more transcriptive).
    pub jsd_from_transcriptive: f64,

    /// Composite score: 0.0 = transcriptive, 1.0 = cognitive.
    pub composite_score: f64,
}

/// Real-time transcription suspicion signal for sentinel integration.
///
/// Computed from a lightweight streaming assessment of correction patterns
/// during live capture. When `is_suspicious` is true, the sentinel should:
/// - Increase checkpoint frequency (more evidence collection)
/// - Annotate the next checkpoint with the suspicion flag
/// - Capture higher-resolution timing data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TranscriptionSuspicion {
    /// Whether the correction pattern is suspicious enough to trigger gating.
    pub is_suspicious: bool,
    /// Ratio of unexplained corrections to total keystrokes.
    pub unexplained_correction_ratio: f64,
    /// Current composite error ecology score (0.0 = transcriptive, 1.0 = cognitive).
    /// Only meaningful when `sample_count >= MIN_SAMPLES`.
    pub ecology_score: f64,
    /// Number of samples assessed so far.
    pub sample_count: usize,
}

/// Threshold for unexplained-corrections-to-keystrokes ratio above which
/// the sentinel raises a transcription suspicion flag.
/// Raised from 0.15 to 0.25: the original threshold flagged normal writers
/// who pause before correcting typos (non-rapid bulk deletions).
const TRANSCRIPTION_SUSPICION_THRESHOLD: f64 = 0.25;

/// Minimum sample count before transcription suspicion can fire.
/// Short sessions produce noisy ratios; require enough data for a stable signal.
const TRANSCRIPTION_MIN_SAMPLES: usize = 100;

/// Lightweight streaming assessment of correction patterns for real-time use.
///
/// Unlike `analyze_error_ecology` which produces full metrics, this function
/// is designed for incremental evaluation during live capture. It counts
/// correction keystrokes that don't fit the cognitive error profile (not rapid,
/// not small) and flags sessions where the ratio exceeds the threshold.
pub fn assess_transcription_suspicion(
    samples: &[SimpleJitterSample],
) -> TranscriptionSuspicion {
    let sample_count = samples.len();
    if sample_count < MIN_SAMPLES {
        return TranscriptionSuspicion {
            sample_count,
            ..Default::default()
        };
    }

    let total_keystrokes = sample_count;
    let mut unexplained_corrections: usize = 0;
    let mut total_corrections: usize = 0;

    let mut consecutive_corrections: usize = 0;
    for i in 0..samples.len() {
        if samples[i].zone == CORRECTION_ZONE {
            total_corrections += 1;
            consecutive_corrections += 1;

            // Check if this correction fits cognitive patterns
            let is_rapid = if i > 0 {
                let iki = samples[i]
                    .timestamp_ns
                    .saturating_sub(samples[i - 1].timestamp_ns) as u64;
                iki < RAPID_CORRECTION_NS
            } else {
                false
            };

            // If not rapid and part of a bulk deletion, it's unexplained
            if !is_rapid && consecutive_corrections >= BULK_CORRECTION_MIN {
                unexplained_corrections += 1;
            }
        } else {
            consecutive_corrections = 0;
        }
    }

    let unexplained_correction_ratio = if total_keystrokes > 0 {
        unexplained_corrections as f64 / total_keystrokes as f64
    } else {
        0.0
    };

    // Compute ecology score if we have enough corrections
    let ecology_score = if total_corrections >= MIN_CORRECTIONS {
        analyze_error_ecology(samples)
            .map(|m| m.composite_score)
            .unwrap_or(0.2)
    } else {
        0.5
    };

    // Require ALL of: enough data, high unexplained ratio, AND low ecology score.
    // The old OR logic flagged normal writers who paused before correcting typos.
    let is_suspicious = sample_count >= TRANSCRIPTION_MIN_SAMPLES
        && unexplained_correction_ratio > TRANSCRIPTION_SUSPICION_THRESHOLD
        && total_corrections >= MIN_CORRECTIONS
        && ecology_score < 0.4;

    TranscriptionSuspicion {
        is_suspicious,
        unexplained_correction_ratio,
        ecology_score,
        sample_count,
    }
}

/// Analyze error ecology from jitter samples.
pub fn analyze_error_ecology(samples: &[SimpleJitterSample]) -> Option<ErrorEcologyMetrics> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }

    let corrections = classify_corrections(samples);
    if corrections.len() < MIN_CORRECTIONS {
        return None;
    }

    let total = corrections.len() as f64;
    let mut type_counts = [0usize; 5];
    for c in &corrections {
        match c.error_type {
            ErrorType::RapidSelfCorrection => type_counts[0] += 1,
            ErrorType::ImmediateSmallCorrection => type_counts[1] += 1,
            ErrorType::DelayedCorrection => type_counts[2] += 1,
            ErrorType::BulkCorrection => type_counts[3] += 1,
            ErrorType::FalseStart => type_counts[4] += 1,
        }
    }

    let ecology: Vec<f64> = type_counts.iter().map(|&c| c as f64 / total).collect();
    let correction_rate = corrections.len() as f64 / samples.len() as f64;

    // Smooth ecology vector to avoid zero-division in JSD.
    let epsilon = 0.001;
    let smoothed: Vec<f64> = ecology.iter().map(|&p| p + epsilon).collect();
    let smooth_sum: f64 = smoothed.iter().sum();
    let normalized: Vec<f64> = smoothed.iter().map(|&p| p / smooth_sum).collect();

    let jsd_cognitive = jensen_shannon_divergence(&normalized, &COGNITIVE_REFERENCE);
    let jsd_transcriptive = jensen_shannon_divergence(&normalized, &TRANSCRIPTIVE_REFERENCE);

    // Composite: relative closeness to cognitive vs transcriptive reference.
    let composite_score = if jsd_cognitive + jsd_transcriptive > 0.0 {
        jsd_transcriptive / (jsd_cognitive + jsd_transcriptive)
    } else {
        0.5
    };

    Some(ErrorEcologyMetrics {
        rapid_self_correction_pct: ecology[0],
        immediate_small_correction_pct: ecology[1],
        delayed_correction_pct: ecology[2],
        bulk_correction_pct: ecology[3],
        false_start_pct: ecology[4],
        total_corrections: corrections.len(),
        correction_rate,
        jsd_from_cognitive: jsd_cognitive,
        jsd_from_transcriptive: jsd_transcriptive,
        composite_score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn make_sample(zone: u8, iki_ms: u64) -> SimpleJitterSample {
        SimpleJitterSample {
            duration_since_last_ns: iki_ms * 1_000_000,
            zone,
            ..Default::default()
        }
    }

    fn make_stream(pattern: &[(u8, u64)]) -> Vec<SimpleJitterSample> {
        let mut ts = 0i64;
        pattern
            .iter()
            .map(|&(zone, iki_ms)| {
                let iki_ns = iki_ms * 1_000_000;
                ts += iki_ns as i64;
                SimpleJitterSample {
                    timestamp_ns: ts,
                    duration_since_last_ns: iki_ns,
                    zone,
                    ..Default::default()
                }
            })
            .collect()
    }

    #[test]
    fn test_jsd_identical() {
        let p = vec![0.5, 0.3, 0.2];
        assert!(jensen_shannon_divergence(&p, &p) < 0.001);
    }

    #[test]
    fn test_jsd_different() {
        let p = vec![0.9, 0.05, 0.05];
        let q = vec![0.05, 0.05, 0.9];
        let jsd = jensen_shannon_divergence(&p, &q);
        assert!(jsd > 0.5, "very different distributions should have high JSD: {}", jsd);
    }

    #[test]
    fn test_classify_rapid_self_correction() {
        // Type several chars, then quickly backspace 2.
        let mut pattern: Vec<(u8, u64)> = (0..15).map(|_| (1u8, 100)).collect();
        // Quick correction: zone=0xFF, IKI < 500ms, 2 chars.
        pattern.push((0xFF, 200));
        pattern.push((0xFF, 150));
        // Resume typing.
        pattern.extend((0..10).map(|_| (2u8, 120)));

        let samples = make_stream(&pattern);
        let corrections = classify_corrections(&samples);
        assert!(!corrections.is_empty());
        assert_eq!(corrections[0].error_type, ErrorType::RapidSelfCorrection);
    }

    #[test]
    fn test_classify_bulk_correction() {
        let mut pattern: Vec<(u8, u64)> = (0..15).map(|_| (1u8, 100)).collect();
        // Bulk delete: 6 consecutive corrections.
        for _ in 0..6 {
            pattern.push((0xFF, 100));
        }
        pattern.extend((0..10).map(|_| (2u8, 120)));

        let samples = make_stream(&pattern);
        let corrections = classify_corrections(&samples);
        assert!(!corrections.is_empty());
        assert_eq!(corrections[0].error_type, ErrorType::BulkCorrection);
    }

    #[test]
    fn test_classify_delayed_correction() {
        let mut pattern: Vec<(u8, u64)> = (0..15).map(|_| (1u8, 100)).collect();
        // Delayed correction: long pause then delete.
        pattern.push((0xFF, 3000)); // 3s pause before correction.
        pattern.push((0xFF, 100));
        pattern.extend((0..10).map(|_| (2u8, 120)));

        let samples = make_stream(&pattern);
        let corrections = classify_corrections(&samples);
        assert!(!corrections.is_empty());
        assert_eq!(corrections[0].error_type, ErrorType::DelayedCorrection);
    }

    #[test]
    fn test_insufficient_data() {
        let samples = make_stream(&[(1, 100); 10]);
        assert!(analyze_error_ecology(&samples).is_none());
    }

    #[test]
    fn test_cognitive_pattern() {
        // Mostly rapid self-corrections and false starts.
        let mut pattern: Vec<(u8, u64)> = Vec::new();
        for _ in 0..5 {
            // Type, quick correct, type.
            pattern.extend((0..8).map(|_| (1u8, 100)));
            pattern.push((0xFF, 200));
            pattern.push((0xFF, 150));
            pattern.extend((0..3).map(|_| (2u8, 120)));
        }
        // Pad to MIN_SAMPLES.
        pattern.extend((0..10).map(|_| (3u8, 130)));

        let samples = make_stream(&pattern);
        let result = analyze_error_ecology(&samples);
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(
            m.rapid_self_correction_pct > 0.3,
            "cognitive pattern should have high rapid corrections: {}",
            m.rapid_self_correction_pct
        );
    }

    #[test]
    fn test_transcriptive_pattern() {
        // Mostly delayed and bulk corrections.
        let mut pattern: Vec<(u8, u64)> = Vec::new();
        for _ in 0..6 {
            // Type steadily, then delayed bulk correction.
            pattern.extend((0..8).map(|_| (1u8, 150)));
            // Long pause then bulk delete.
            pattern.push((0xFF, 3000));
            for _ in 0..5 {
                pattern.push((0xFF, 100));
            }
        }
        pattern.extend((0..5).map(|_| (2u8, 140)));

        let samples = make_stream(&pattern);
        let result = analyze_error_ecology(&samples);
        assert!(result.is_some());
        let m = result.unwrap();
        let non_rapid = m.delayed_correction_pct + m.bulk_correction_pct;
        assert!(
            non_rapid > 0.4,
            "transcriptive should have high delayed+bulk: {}",
            non_rapid
        );
    }

    #[test]
    fn test_composite_score_range() {
        let mut pattern: Vec<(u8, u64)> = Vec::new();
        for _ in 0..8 {
            pattern.extend((0..5).map(|_| (1u8, 100)));
            pattern.push((0xFF, 200));
        }
        pattern.extend((0..10).map(|_| (2u8, 110)));

        let samples = make_stream(&pattern);
        if let Some(m) = analyze_error_ecology(&samples) {
            assert!(m.composite_score >= 0.0 && m.composite_score <= 1.0);
        }
    }
}
