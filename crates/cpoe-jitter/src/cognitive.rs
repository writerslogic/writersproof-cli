// SPDX-License-Identifier: Apache-2.0

//! Cognitive vs transcriptive writing differentiation via temporal microstructure.
//!
//! Two timing-only classifiers that work on raw inter-keystroke intervals (IKI):
//! - **Sentence Initiation Delay Ratio**: cognitive writers pause significantly
//!   longer before new sentences (thinking) vs transcribers (just reading next line).
//! - **Bigram Fluency Differential**: cognitive writers type common letter pairs
//!   much faster than rare ones (motor memory); transcribers are more uniform.

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
    *b"al", *b"an", *b"ar", *b"as", *b"at", *b"be", *b"ce", *b"ch", *b"co", *b"de", *b"ea", *b"ed",
    *b"en", *b"er", *b"es", *b"ha", *b"he", *b"hi", *b"ic", *b"in", *b"io", *b"is", *b"it", *b"le",
    *b"li", *b"ll", *b"ma", *b"me", *b"nd", *b"ne", *b"ng", *b"nt", *b"of", *b"om", *b"on", *b"or",
    *b"ou", *b"ra", *b"re", *b"ri", *b"ro", *b"se", *b"si", *b"st", *b"te", *b"th", *b"ti", *b"to",
    *b"ur", *b"ve",
];

/// Histogram bin width for IKI median estimation (5 ms in µs).
const MEDIAN_BIN_WIDTH_US: u64 = 5_000;
/// Number of histogram bins covering IKIs up to 5 seconds (5_000_000 / 5_000).
const MEDIAN_NUM_BINS: usize = 1_000;
/// Maximum sentence-initial IKIs tracked on the stack.
const MAX_SENTENCE_STARTS: usize = 512;

/// Find the approximate median value from a histogram of IKI measurements.
/// Returns the center of the median bin in microseconds.
fn histogram_median_value(hist: &[u32], total: u32, bin_width: u64) -> f64 {
    let target = total / 2;
    let mut cumulative = 0u32;
    for (i, &count) in hist.iter().enumerate() {
        cumulative += count;
        if cumulative > target {
            return (i as f64 + 0.5) * bin_width as f64;
        }
    }
    (hist.len() as f64 - 0.5) * bin_width as f64
}

/// Analyze cognitive vs transcriptive writing from timed keystrokes.
///
/// Requires at least 20 keystrokes and 3 sentence boundaries for meaningful results.
pub fn analyze_cognitive_temporal(
    keystrokes: &[TimedKeystroke],
) -> Option<CognitiveTemporalMetrics> {
    if keystrokes.len() < 20 {
        return None;
    }

    let sentence_metrics = compute_sentence_initiation(keystrokes)?;
    let bigram_metrics = compute_bigram_fluency(keystrokes);
    let modality = compute_iki_modality(keystrokes);

    let sid_score = sentence_initiation_to_probability(sentence_metrics.0, sentence_metrics.1);
    let bigram_score = bigram_fluency_to_probability(bigram_metrics.0);

    // Combine all three temporal signals with confidence-adaptive weighting.
    // Sentence initiation is the strongest (hardest to fake).
    // Modality is second (requires realistic multi-modal timing).
    // Bigram fluency is third (can be partially faked with practice).
    let cognitive_probability = if sentence_metrics.2 >= 3 && bigram_metrics.1 >= 30 {
        let bigram_confidence = (bigram_score - 0.5).abs() * 2.0;
        let bigram_weight = 0.2 * bigram_confidence;
        sid_score * 0.45
            + modality * 0.35
            + bigram_score * bigram_weight
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
///
/// Uses a stack-allocated histogram (`[u32; MEDIAN_NUM_BINS]`, 4 KiB) for
/// within-sentence IKI median estimation and a fixed-size array for
/// sentence-initial IKIs, avoiding all heap allocation.
fn compute_sentence_initiation(keystrokes: &[TimedKeystroke]) -> Option<(f64, f64, usize)> {
    let mut within_hist = [0u32; MEDIAN_NUM_BINS];
    let mut within_count = 0u32;
    let mut sentence_ikis = [0u64; MAX_SENTENCE_STARTS];
    let mut sentence_count = 0usize;

    for ks in keystrokes {
        if ks.iki_us == 0 {
            continue;
        }
        if ks.after_sentence_end {
            if sentence_count < MAX_SENTENCE_STARTS {
                sentence_ikis[sentence_count] = ks.iki_us;
                sentence_count += 1;
            }
        } else {
            let bin = (ks.iki_us / MEDIAN_BIN_WIDTH_US).min((MEDIAN_NUM_BINS - 1) as u64) as usize;
            within_hist[bin] += 1;
            within_count += 1;
        }
    }

    if sentence_count < 3 || within_count < 10 {
        return None;
    }

    // Approximate median from histogram (5 ms resolution).
    let median_within = histogram_median_value(&within_hist, within_count, MEDIAN_BIN_WIDTH_US);
    if median_within < 1.0 {
        return None;
    }

    // Compute per-sentence initiation ratios inline (no intermediate Vec).
    let sentence_ikis = &sentence_ikis[..sentence_count];
    let ratio_sum: f64 = sentence_ikis
        .iter()
        .map(|&iki| iki as f64 / median_within)
        .sum();
    let mean_ratio = ratio_sum / sentence_count as f64;
    let variance = if sentence_count > 1 {
        sentence_ikis
            .iter()
            .map(|&iki| {
                let r = iki as f64 / median_within;
                (r - mean_ratio).powi(2)
            })
            .sum::<f64>()
            / (sentence_count - 1) as f64
    } else {
        0.0
    };

    Some((mean_ratio, variance, sentence_count))
}

/// Returns (fluency_ratio, total_bigram_pairs).
///
/// Uses two stack-allocated histograms (`[u32; MEDIAN_NUM_BINS]`, 4 KiB each)
/// to compute approximate medians without heap-sorting IKI vectors.
fn compute_bigram_fluency(keystrokes: &[TimedKeystroke]) -> (f64, usize) {
    let mut common_hist = [0u32; MEDIAN_NUM_BINS];
    let mut rare_hist = [0u32; MEDIAN_NUM_BINS];
    let mut common_count = 0u32;
    let mut rare_count = 0u32;

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

        let bin = (pair[1].iki_us / MEDIAN_BIN_WIDTH_US).min((MEDIAN_NUM_BINS - 1) as u64) as usize;
        let bigram = [prev, curr];
        if is_common_bigram(&bigram) {
            common_hist[bin] += 1;
            common_count += 1;
        } else {
            rare_hist[bin] += 1;
            rare_count += 1;
        }
    }

    let total = (common_count + rare_count) as usize;
    if common_count < 10 || rare_count < 10 {
        return (1.0, total); // Insufficient data, neutral ratio
    }

    // Approximate median from histogram bins.
    let median_common = histogram_median_value(&common_hist, common_count, MEDIAN_BIN_WIDTH_US);
    let median_rare = histogram_median_value(&rare_hist, rare_count, MEDIAN_BIN_WIDTH_US);

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
///
/// Fully streaming: bins IKIs into a stack-allocated histogram in a single
/// pass, computing count, sum, and sum-of-squares for the CV alongside.
/// Zero heap allocations regardless of input size.
pub fn compute_iki_modality(keystrokes: &[TimedKeystroke]) -> f64 {
    // Bin IKIs into 50ms buckets (0-50, 50-100, ..., up to 2000ms = 40 bins).
    const BIN_WIDTH: u64 = 50_000; // 50ms in µs
    const NUM_BINS: usize = 40;
    let mut bins = [0u32; NUM_BINS];
    let mut count: u64 = 0;
    let mut sum: u64 = 0;
    let mut sum_sq: u128 = 0;

    for k in keystrokes {
        let iki = k.iki_us;
        if iki == 0 || iki >= 5_000_000 {
            continue;
        }
        count += 1;
        sum += iki;
        sum_sq += (iki as u128) * (iki as u128);
        let bin = (iki / BIN_WIDTH).min(NUM_BINS as u64 - 1) as usize;
        bins[bin] += 1;
    }

    if count < 50 {
        return 0.5; // Insufficient data.
    }

    // Find local maxima (peaks) in the histogram.
    // A bin is a peak if it's higher than both neighbors by at least 3% of total.
    let total = count as f64;
    let threshold = total * 0.03;
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

    // Coefficient of variation from streaming sums (no intermediate Vec).
    // Sample variance = (sum_sq - sum * mean) / (n - 1).
    let mean = sum as f64 / count as f64;
    let variance = (sum_sq as f64 - sum as f64 * mean) / (count - 1) as f64;
    let cv = libm::sqrt(variance.max(0.0)) / mean;

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
            "ratio={}",
            metrics.sentence_initiation_ratio
        );
        assert!(
            metrics.cognitive_probability > 0.6,
            "prob={}",
            metrics.cognitive_probability
        );
    }

    #[test]
    fn test_transcriptive_detected() {
        let ks = make_transcriptive_keystrokes();
        let metrics = analyze_cognitive_temporal(&ks).unwrap();
        assert!(
            metrics.sentence_initiation_ratio < 4.0,
            "ratio={}",
            metrics.sentence_initiation_ratio
        );
        assert!(
            metrics.cognitive_probability < 0.5,
            "prob={}",
            metrics.cognitive_probability
        );
    }

    #[test]
    fn test_insufficient_data_returns_none() {
        let ks = vec![
            TimedKeystroke {
                iki_us: 100_000,
                char_byte: b'a',
                after_sentence_end: false,
            },
            TimedKeystroke {
                iki_us: 100_000,
                char_byte: b'b',
                after_sentence_end: false,
            },
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
