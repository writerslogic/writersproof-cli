// SPDX-License-Identifier: Apache-2.0

//! Cognitive vs transcriptive writing differentiation via temporal microstructure.
//!
//! Two timing-only classifiers that work on raw inter-keystroke intervals (IKI):
//! - **Sentence Initiation Delay Ratio**: cognitive writers pause significantly
//!   longer before new sentences (thinking) vs transcribers (just reading next line).
//! - **Bigram Fluency Differential**: cognitive writers type common letter pairs
//!   much faster than rare ones (motor memory); transcribers are more uniform.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Result of cognitive temporal analysis on a keystroke timing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveTemporalMetrics {
    /// Ratio of mean sentence-initial pause to median within-sentence IKI.
    /// Cognitive: 8-30x, Transcriptive: 2-4x.
    pub sentence_initiation_ratio: f64,
    /// Variance of sentence initiation ratios across sentences.
    /// Cognitive: high (some sentences flow, others need thought).
    /// Transcriptive: low (uniform reading pace).
    pub sentence_initiation_variance: f64,
    /// Ratio of common bigram speed to rare bigram speed.
    /// Cognitive: >2.5 (automated motor sequences vs novel planning).
    /// Transcriptive: <1.5 (uniform visual-motor transfer).
    pub bigram_fluency_ratio: f64,
    /// IKI distribution modality score [0, 1].
    /// Cognitive: multi-modal (>0.7), Transcriptive: unimodal (<0.3).
    pub iki_modality_score: f64,
    /// Combined cognitive probability [0, 1].
    /// 0 = strongly transcriptive, 1 = strongly cognitive.
    pub cognitive_probability: f64,
    /// Number of sentences analyzed.
    pub sentence_count: usize,
    /// Number of bigram pairs analyzed.
    pub bigram_pairs_analyzed: usize,
}

/// A keystroke event with timing and character identity.
#[derive(Debug, Clone, Copy)]
pub struct TimedKeystroke {
    /// Inter-keystroke interval in microseconds (time since previous key).
    pub iki_us: u64,
    /// The character typed (ASCII byte; 0 for non-printable).
    pub char_byte: u8,
    /// Whether this keystroke follows a sentence-ending punctuation.
    pub after_sentence_end: bool,
}

/// Top 50 most common English bigrams (sorted for binary search).
/// Source: Peter Norvig corpus analysis / Mayzner & Tresselt.
const COMMON_BIGRAMS: &[[u8; 2]] = &[
    *b"al", *b"an", *b"ar", *b"as", *b"at", *b"be", *b"ce", *b"ch",
    *b"co", *b"de", *b"ea", *b"ed", *b"en", *b"er", *b"es", *b"ha",
    *b"he", *b"hi", *b"ic", *b"in", *b"io", *b"is", *b"it", *b"le",
    *b"li", *b"ll", *b"ma", *b"me", *b"nd", *b"ne", *b"ng", *b"nt",
    *b"of", *b"om", *b"on", *b"or", *b"ou", *b"ra", *b"re", *b"ri",
    *b"ro", *b"se", *b"si", *b"st", *b"te", *b"th", *b"ti", *b"to",
    *b"ur", *b"ve",
];

/// Analyze cognitive vs transcriptive writing from timed keystrokes.
///
/// Requires at least 20 keystrokes and 3 sentence boundaries for meaningful results.
pub fn analyze_cognitive_temporal(keystrokes: &[TimedKeystroke]) -> Option<CognitiveTemporalMetrics> {
    if keystrokes.len() < 20 {
        return None;
    }

    let sentence_metrics = compute_sentence_initiation(keystrokes)?;
    let bigram_metrics = compute_bigram_fluency(keystrokes);
    let modality = compute_iki_modality(keystrokes);

    let sid_score = sentence_initiation_to_probability(
        sentence_metrics.0,
        sentence_metrics.1,
    );
    let bigram_score = bigram_fluency_to_probability(bigram_metrics.0);

    // Combine all three temporal signals with confidence-adaptive weighting.
    // Sentence initiation is the strongest (hardest to fake).
    // Modality is second (requires realistic multi-modal timing).
    // Bigram fluency is third (can be partially faked with practice).
    let cognitive_probability = if sentence_metrics.2 >= 3 && bigram_metrics.1 >= 30 {
        let bigram_confidence = (bigram_score - 0.5).abs() * 2.0;
        let bigram_weight = 0.2 * bigram_confidence;
        sid_score * 0.45 + modality * 0.35 + bigram_score * bigram_weight
            + sid_score * (0.2 - bigram_weight) // redistribute unused bigram weight to SID
    } else if sentence_metrics.2 >= 3 {
        sid_score * 0.6 + modality * 0.4
    } else if bigram_metrics.1 >= 30 {
        bigram_score * 0.5 + modality * 0.5
    } else {
        return None; // Insufficient data
    };

    Some(CognitiveTemporalMetrics {
        sentence_initiation_ratio: sentence_metrics.0,
        sentence_initiation_variance: sentence_metrics.1,
        bigram_fluency_ratio: bigram_metrics.0,
        iki_modality_score: modality,
        cognitive_probability,
        sentence_count: sentence_metrics.2,
        bigram_pairs_analyzed: bigram_metrics.1,
    })
}

/// Returns (mean_ratio, variance_of_ratios, sentence_count).
fn compute_sentence_initiation(keystrokes: &[TimedKeystroke]) -> Option<(f64, f64, usize)> {
    // Collect within-sentence IKIs and sentence-initial IKIs.
    let mut within_sentence_ikis: Vec<u64> = Vec::new();
    let mut sentence_initial_ikis: Vec<u64> = Vec::new();

    for ks in keystrokes {
        if ks.iki_us == 0 {
            continue;
        }
        if ks.after_sentence_end {
            sentence_initial_ikis.push(ks.iki_us);
        } else {
            within_sentence_ikis.push(ks.iki_us);
        }
    }

    if sentence_initial_ikis.len() < 3 || within_sentence_ikis.len() < 10 {
        return None;
    }

    // Median within-sentence IKI (robust to outliers).
    within_sentence_ikis.sort_unstable();
    let median_within = within_sentence_ikis[within_sentence_ikis.len() / 2] as f64;
    if median_within < 1.0 {
        return None;
    }

    // Compute per-sentence initiation ratios.
    let ratios: Vec<f64> = sentence_initial_ikis
        .iter()
        .map(|&iki| iki as f64 / median_within)
        .collect();

    let mean_ratio = ratios.iter().sum::<f64>() / ratios.len() as f64;
    let variance = if ratios.len() > 1 {
        ratios.iter().map(|r| (r - mean_ratio).powi(2)).sum::<f64>() / (ratios.len() - 1) as f64
    } else {
        0.0
    };

    Some((mean_ratio, variance, sentence_initial_ikis.len()))
}

/// Returns (fluency_ratio, total_bigram_pairs).
fn compute_bigram_fluency(keystrokes: &[TimedKeystroke]) -> (f64, usize) {
    let mut common_speeds: Vec<u64> = Vec::new();
    let mut rare_speeds: Vec<u64> = Vec::new();

    for pair in keystrokes.windows(2) {
        let prev = pair[0].char_byte.to_ascii_lowercase();
        let curr = pair[1].char_byte.to_ascii_lowercase();

        // Only consider letter pairs with valid timing.
        if !prev.is_ascii_lowercase() || !curr.is_ascii_lowercase() {
            continue;
        }
        if pair[1].iki_us == 0 || pair[1].iki_us > 2_000_000 {
            continue; // Skip zero or >2s gaps (not typing speed)
        }

        let bigram = [prev, curr];
        if is_common_bigram(&bigram) {
            common_speeds.push(pair[1].iki_us);
        } else {
            rare_speeds.push(pair[1].iki_us);
        }
    }

    let total = common_speeds.len() + rare_speeds.len();
    if common_speeds.len() < 10 || rare_speeds.len() < 10 {
        return (1.0, total); // Insufficient data, neutral ratio
    }

    // Use median speed (inverse of IKI) for robustness.
    common_speeds.sort_unstable();
    rare_speeds.sort_unstable();

    let median_common = common_speeds[common_speeds.len() / 2] as f64;
    let median_rare = rare_speeds[rare_speeds.len() / 2] as f64;

    if median_common < 1.0 {
        return (1.0, total);
    }

    // Ratio of rare/common IKI (higher = common bigrams typed faster = cognitive).
    let ratio = median_rare / median_common;
    (ratio, total)
}

fn is_common_bigram(bigram: &[u8; 2]) -> bool {
    COMMON_BIGRAMS.binary_search(bigram).is_ok()
}

/// Map sentence initiation ratio to [0, 1] cognitive probability.
/// Cognitive: ratio 8-30 → high probability.
/// Transcriptive: ratio 2-4 → low probability.
fn sentence_initiation_to_probability(mean_ratio: f64, variance: f64) -> f64 {
    let ratio_score = crate::sigmoid(mean_ratio, 0.5, 6.0);
    let variance_score = crate::sigmoid(variance, 0.2, 10.0);
    ratio_score * 0.7 + variance_score * 0.3
}

/// Map bigram fluency ratio to [0, 1] cognitive probability.
/// Cognitive: ratio > 2.5. Transcriptive: ratio < 1.5.
fn bigram_fluency_to_probability(ratio: f64) -> f64 {
    crate::sigmoid(ratio, 2.0, 2.0)
}

/// IKI distribution multi-modality analysis.
///
/// Cognitive writing produces a multi-modal IKI distribution:
/// - Mode 1 (fast): 50-150ms — automated motor sequences within words
/// - Mode 2 (medium): 150-400ms — word boundaries and common phrases
/// - Mode 3 (slow): 400ms+ — thinking pauses (lexical retrieval, planning)
///
/// Transcription produces a unimodal distribution centered on the reading+typing speed.
///
/// Returns a modality score: 1.0 = clearly multi-modal (cognitive),
/// 0.0 = unimodal (transcriptive).
pub fn compute_iki_modality(keystrokes: &[TimedKeystroke]) -> f64 {
    let ikis: Vec<u64> = keystrokes
        .iter()
        .map(|k| k.iki_us)
        .filter(|&iki| iki > 0 && iki < 5_000_000)
        .collect();

    if ikis.len() < 50 {
        return 0.5; // Insufficient data.
    }

    // Bin IKIs into 50ms buckets (0-50, 50-100, ..., up to 2000ms = 40 bins).
    const BIN_WIDTH: u64 = 50_000; // 50ms in µs
    const NUM_BINS: usize = 40;
    let mut bins = [0u32; NUM_BINS];

    for &iki in &ikis {
        let bin = (iki / BIN_WIDTH).min(NUM_BINS as u64 - 1) as usize;
        bins[bin] += 1;
    }

    // Find local maxima (peaks) in the histogram.
    // A bin is a peak if it's higher than both neighbors by at least 5% of total.
    let total = ikis.len() as f64;
    let threshold = total * 0.03; // 3% of total to count as significant peak
    let mut peaks = 0u32;

    for i in 1..NUM_BINS - 1 {
        let current = bins[i] as f64;
        let left = bins[i - 1] as f64;
        let right = bins[i + 1] as f64;
        if current > left && current > right && current > threshold {
            peaks += 1;
        }
    }
    // Check edges.
    if bins[0] as f64 > bins[1] as f64 && bins[0] as f64 > threshold {
        peaks += 1;
    }

    // Also compute the coefficient of variation of the distribution.
    // High CV = spread-out distribution (cognitive). Low CV = tight (transcriptive).
    let mean = ikis.iter().sum::<u64>() as f64 / ikis.len() as f64;
    let variance = ikis.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>()
        / (ikis.len() - 1) as f64;
    let cv = variance.sqrt() / mean;

    // Combine: peaks indicate modes, CV indicates spread.
    // Cognitive: 3+ peaks and CV > 0.8. Transcriptive: 1 peak and CV < 0.4.
    const PEAK_SCORE_1: f64 = 0.1;
    const PEAK_SCORE_2: f64 = 0.5;
    const PEAK_SCORE_3: f64 = 0.8;
    const PEAK_SCORE_MANY: f64 = 0.95;
    const CV_SIGMOID_STEEPNESS: f64 = 5.0;
    const CV_SIGMOID_MIDPOINT: f64 = 0.6;
    const PEAK_WEIGHT: f64 = 0.5;

    let peak_score = match peaks {
        0 | 1 => PEAK_SCORE_1,
        2 => PEAK_SCORE_2,
        3 => PEAK_SCORE_3,
        _ => PEAK_SCORE_MANY,
    };
    let cv_score = crate::sigmoid(cv, CV_SIGMOID_STEEPNESS, CV_SIGMOID_MIDPOINT);

    peak_score * PEAK_WEIGHT + cv_score * (1.0 - PEAK_WEIGHT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cognitive_keystrokes() -> Vec<TimedKeystroke> {
        let mut ks = Vec::new();
        // Simulate cognitive writing: long pauses at sentence starts, variable within.
        // 5 sentences to ensure >= 3 sentence boundaries after first.
        let sentences: &[&[u8]] = &[
            b"The quick brown fox jumps over the lazy dog near the river bank.",
            b"A second thought emerges from the depths of creative thinking here.",
            b"Perhaps the reader will notice something unusual about this text.",
            b"Writing from memory produces irregular rhythms and varied pauses.",
            b"The final sentence wraps up the cognitive composition naturally.",
        ];
        let sentence_pauses = [0u64, 800_000, 1_500_000, 2_200_000, 600_000];
        for (si, sentence) in sentences.iter().enumerate() {
            for (ci, &ch) in sentence.iter().enumerate() {
                let after_sentence_end = si > 0 && ci == 0;
                let iki = if after_sentence_end {
                    sentence_pauses[si] // Variable thinking pauses (0.6-2.2s)
                } else if ch == b' ' {
                    180_000
                } else {
                    120_000 + ((ch as u64 * 7) % 80_000)
                };
                ks.push(TimedKeystroke {
                    iki_us: iki,
                    char_byte: ch,
                    after_sentence_end,
                });
            }
        }
        ks
    }

    fn make_transcriptive_keystrokes() -> Vec<TimedKeystroke> {
        let mut ks = Vec::new();
        // Simulate transcription: uniform pace, short sentence-start pauses.
        let sentences: &[&[u8]] = &[
            b"The quick brown fox jumps over the lazy dog near the river bank.",
            b"A second thought emerges from the depths of creative thinking here.",
            b"Perhaps the reader will notice something unusual about this text.",
            b"Writing from memory produces irregular rhythms and varied pauses.",
            b"The final sentence wraps up the cognitive composition naturally.",
        ];
        for (si, sentence) in sentences.iter().enumerate() {
            for (ci, &ch) in sentence.iter().enumerate() {
                let after_sentence_end = si > 0 && ci == 0;
                let iki = if after_sentence_end {
                    300_000 // just reading next line: 300ms
                } else {
                    110_000 // uniform typing
                };
                ks.push(TimedKeystroke {
                    iki_us: iki,
                    char_byte: ch,
                    after_sentence_end,
                });
            }
        }
        ks
    }

    #[test]
    fn test_cognitive_detected() {
        let ks = make_cognitive_keystrokes();
        let metrics = analyze_cognitive_temporal(&ks).unwrap();
        assert!(
            metrics.sentence_initiation_ratio > 5.0,
            "ratio={}", metrics.sentence_initiation_ratio
        );
        assert!(
            metrics.cognitive_probability > 0.6,
            "prob={}", metrics.cognitive_probability
        );
    }

    #[test]
    fn test_transcriptive_detected() {
        let ks = make_transcriptive_keystrokes();
        let metrics = analyze_cognitive_temporal(&ks).unwrap();
        assert!(
            metrics.sentence_initiation_ratio < 4.0,
            "ratio={}", metrics.sentence_initiation_ratio
        );
        assert!(
            metrics.cognitive_probability < 0.5,
            "prob={}", metrics.cognitive_probability
        );
    }

    #[test]
    fn test_insufficient_data_returns_none() {
        let ks = vec![
            TimedKeystroke { iki_us: 100_000, char_byte: b'a', after_sentence_end: false },
            TimedKeystroke { iki_us: 100_000, char_byte: b'b', after_sentence_end: false },
        ];
        assert!(analyze_cognitive_temporal(&ks).is_none());
    }

    #[test]
    fn test_bigram_common_lookup() {
        assert!(is_common_bigram(b"th"));
        assert!(is_common_bigram(b"he"));
        assert!(!is_common_bigram(b"qx"));
        assert!(!is_common_bigram(b"zv"));
    }
}
