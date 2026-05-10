// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Cognitive Load-Timing Entanglement analysis.
//!
//! Measures the causal coupling between linguistic difficulty and typing timing
//! at three scales:
//!
//! - **Word scale**: Spearman correlation between IKI and n-gram surprisal.
//!   Cognitive writers pause longer before rare/complex words (rho 0.3-0.6).
//!   Transcriptive writers show rho near zero (pauses reflect source reading).
//!
//! - **Clause scale**: Per-sentence velocity arc fitting. Cognitive writers
//!   show a planning-execution arc (slow onset → acceleration → deceleration).
//!   Transcriptive writers produce flat velocity curves.
//!
//! - **Document scale**: Mutual information between deep pauses (>3s) and
//!   structural boundaries (sentence/paragraph ends). Cognitive writers
//!   concentrate deep pauses at structural joints.

use serde::{Deserialize, Serialize};

use crate::jitter::SimpleJitterSample;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum samples for meaningful analysis.
const MIN_SAMPLES: usize = 30;

/// Minimum words for surprisal correlation.
const MIN_WORDS_FOR_CORRELATION: usize = 15;

/// Pause threshold for structural boundary analysis (3 seconds).
const STRUCTURAL_PAUSE_NS: u64 = 3_000_000_000;

/// Sentence boundary characters.
const SENTENCE_TERMINATORS: &[char] = &['.', '!', '?'];

/// Paragraph break marker.
const PARAGRAPH_BREAK: &str = "\n\n";

// ---------------------------------------------------------------------------
// Trigram surprisal model
// ---------------------------------------------------------------------------

/// Unigram log-probability estimates (bits) for English words.
/// Built from frequency data; higher = rarer = more surprising.
/// This is a lightweight model — a proper trigram corpus would be better
/// but this captures the essential correlation structure.
fn word_surprisal(word: &str) -> f64 {
    let lower = word.to_ascii_lowercase();
    match lower.as_str() {
        // Top-20 most common English words (~1.5 bits)
        "the" | "be" | "to" | "of" | "and" | "a" | "in" | "that" | "have" | "i" | "it"
        | "for" | "not" | "on" | "with" | "he" | "as" | "you" | "do" | "at" => 1.5,

        // Next tier: common function words (~2.5 bits)
        "this" | "but" | "his" | "by" | "from" | "they" | "we" | "say" | "her" | "she"
        | "or" | "an" | "will" | "my" | "one" | "all" | "would" | "there" | "their"
        | "what" | "so" | "up" | "out" | "if" | "about" | "who" | "get" | "which" | "go"
        | "me" | "when" | "make" | "can" | "like" | "no" | "just" | "him" | "know"
        | "take" | "come" | "could" | "than" | "look" | "want" | "give" | "use" | "find"
        | "here" | "thing" | "many" | "well" | "only" | "also" | "how" | "after" | "its"
        | "our" | "two" | "way" | "then" | "some" | "them" | "see" | "other" | "been"
        | "into" | "has" | "more" | "time" | "very" | "new" | "was" | "were"
        | "had" | "are" | "is" | "did" | "does" | "being" | "am" => 2.5,

        // Common content words (~4.0 bits)
        "people" | "because" | "good" | "each" | "those" | "feel" | "seem" | "own"
        | "think" | "same" | "tell" | "need" | "should" | "try" | "leave" | "call"
        | "keep" | "let" | "begin" | "show" | "hear" | "play" | "run" | "move" | "live"
        | "believe" | "bring" | "happen" | "write" | "provide" | "sit" | "stand" | "lose"
        | "pay" | "meet" | "include" | "continue" | "set" | "learn" | "change" | "lead"
        | "understand" | "watch" | "follow" | "stop" | "create" | "speak" | "read"
        | "allow" | "add" | "spend" | "grow" | "open" | "walk" | "offer" | "remember"
        | "hold" | "love" | "consider" | "appear" | "buy" | "wait" | "serve" | "die"
        | "send" | "expect" | "build" | "stay" | "fall" | "oh" | "cut" | "reach"
        | "remain" | "suggest" | "raise" | "pass" | "sell" | "require" | "report"
        | "decide" | "pull" => 4.0,

        _ => {
            // Estimate based on word length: longer words tend to be rarer.
            let len = lower.len();
            if len <= 3 {
                3.5
            } else if len <= 5 {
                5.0
            } else if len <= 8 {
                6.5
            } else if len <= 12 {
                8.0
            } else {
                10.0
            }
        }
    }
}

/// Compute per-word surprisal for a text, returning (word, surprisal) pairs.
fn compute_word_surprisals(text: &str) -> Vec<(String, f64)> {
    text.split_whitespace()
        .filter(|w| {
            // Skip punctuation-only tokens.
            w.chars().any(|c| c.is_alphanumeric())
        })
        .map(|w| {
            let cleaned: String = w.chars().filter(|c| c.is_alphanumeric()).collect();
            let surprisal = word_surprisal(&cleaned);
            (cleaned, surprisal)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Spearman rank correlation
// ---------------------------------------------------------------------------

/// Compute Spearman rank correlation between two equal-length sequences.
fn spearman_correlation(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len();
    if n < 3 || n != ys.len() {
        return 0.0;
    }

    let rank = |vals: &[f64]| -> Vec<f64> {
        let mut indices: Vec<usize> = (0..n).collect();
        indices.sort_unstable_by(|&a, &b| {
            vals[a]
                .partial_cmp(&vals[b])
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut ranks = vec![0.0f64; n];
        for (rank, &idx) in indices.iter().enumerate() {
            ranks[idx] = rank as f64;
        }
        ranks
    };

    let x_ranks = rank(xs);
    let y_ranks = rank(ys);
    let mean = (n - 1) as f64 / 2.0;

    let num: f64 = (0..n)
        .map(|i| (x_ranks[i] - mean) * (y_ranks[i] - mean))
        .sum();
    let denom_x: f64 = (0..n)
        .map(|i| (x_ranks[i] - mean).powi(2))
        .sum::<f64>()
        .sqrt();
    let denom_y: f64 = (0..n)
        .map(|i| (y_ranks[i] - mean).powi(2))
        .sum::<f64>()
        .sqrt();

    let denom = denom_x * denom_y;
    if denom < f64::EPSILON {
        return 0.0;
    }

    (num / denom).clamp(-1.0, 1.0)
}

// ---------------------------------------------------------------------------
// Word-scale: IKI-surprisal correlation
// ---------------------------------------------------------------------------

/// Compute the correlation between inter-keystroke intervals and word surprisal.
///
/// For each word boundary in the text, we estimate the IKI preceding that word
/// from the jitter samples and correlate it with the word's surprisal.
///
/// Returns the Spearman rho. Cognitive writers: 0.3-0.6. Transcriptive: ~0.
fn compute_iki_surprisal_correlation(
    document_text: &str,
    samples: &[SimpleJitterSample],
) -> Option<f64> {
    let word_surprisals = compute_word_surprisals(document_text);
    if word_surprisals.len() < MIN_WORDS_FOR_CORRELATION || samples.len() < MIN_SAMPLES {
        return None;
    }

    // We don't have exact character-to-keystroke mapping, so we estimate:
    // distribute samples across words proportionally to word length.
    let total_chars: usize = word_surprisals.iter().map(|(w, _)| w.len() + 1).sum(); // +1 for space
    let samples_per_char = samples.len() as f64 / total_chars.max(1) as f64;

    let mut iki_per_word = Vec::with_capacity(word_surprisals.len());
    let mut surprisals = Vec::with_capacity(word_surprisals.len());
    let mut sample_idx = 0usize;

    for (word, surprisal) in &word_surprisals {
        let word_samples = ((word.len() + 1) as f64 * samples_per_char).round() as usize;
        let end_idx = (sample_idx + word_samples).min(samples.len());

        if sample_idx < end_idx {
            // Use the maximum IKI in this word's sample range as the "pre-word pause".
            // The first sample of each word segment captures the inter-word gap.
            let max_iki = samples[sample_idx..end_idx]
                .iter()
                .map(|s| s.duration_since_last_ns)
                .max()
                .unwrap_or(0);

            if max_iki > 0 {
                iki_per_word.push(max_iki as f64);
                surprisals.push(*surprisal);
            }
        }

        sample_idx = end_idx;
    }

    if iki_per_word.len() < MIN_WORDS_FOR_CORRELATION {
        return None;
    }

    Some(spearman_correlation(&iki_per_word, &surprisals))
}

// ---------------------------------------------------------------------------
// Clause-scale: Sentence velocity arc
// ---------------------------------------------------------------------------

/// Per-sentence velocity arc metrics.
#[derive(Debug, Clone, Default)]
struct SentenceArc {
    /// R-squared of quadratic fit (planning-execution arc).
    r_squared: f64,
    /// Number of samples in this sentence.
    sample_count: usize,
}

/// Fit a quadratic curve (planning-execution arc) to per-sentence IKI sequences.
///
/// Returns mean R-squared across all sentences with enough samples.
/// Cognitive writers: R² > 0.3 (good fit to arc). Transcriptive: R² < 0.1.
fn compute_sentence_velocity_arcs(
    document_text: &str,
    samples: &[SimpleJitterSample],
) -> Option<f64> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }

    // Split text into sentences.
    let sentences = split_into_sentences(document_text);
    if sentences.len() < 3 {
        return None;
    }

    // Distribute samples across sentences proportionally to character count.
    let total_chars: usize = sentences.iter().map(|s| s.len()).sum();
    if total_chars == 0 {
        return None;
    }
    let samples_per_char = samples.len() as f64 / total_chars as f64;

    let mut arcs = Vec::new();
    let mut sample_idx = 0usize;

    for sentence in &sentences {
        let sentence_samples =
            (sentence.len() as f64 * samples_per_char).round().max(1.0) as usize;
        let end_idx = (sample_idx + sentence_samples).min(samples.len());

        if end_idx - sample_idx >= 5 {
            // Extract IKI values for this sentence.
            let ikis: Vec<f64> = samples[sample_idx..end_idx]
                .iter()
                .map(|s| s.duration_since_last_ns as f64)
                .collect();

            let r_sq = quadratic_r_squared(&ikis);
            arcs.push(SentenceArc {
                r_squared: r_sq,
                sample_count: ikis.len(),
            });
        }

        sample_idx = end_idx;
    }

    if arcs.is_empty() {
        return None;
    }

    // Weighted mean R² by sample count.
    let total_weight: usize = arcs.iter().map(|a| a.sample_count).sum();
    let weighted_r_sq: f64 = arcs
        .iter()
        .map(|a| a.r_squared * a.sample_count as f64)
        .sum::<f64>()
        / total_weight as f64;

    Some(weighted_r_sq)
}

/// Fit a quadratic y = a*x² + b*x + c to the sequence and return R².
///
/// Uses Gaussian elimination with partial pivoting on the 3x3 normal equations
/// to avoid catastrophic cancellation that Cramer's rule suffers from.
#[allow(clippy::needless_range_loop)] // Matrix row/col indexing is clearer with explicit indices.
fn quadratic_r_squared(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 3 {
        return 0.0;
    }

    let n_f = n as f64;
    let y_mean = values.iter().sum::<f64>() / n_f;
    let ss_tot: f64 = values.iter().map(|y| (y - y_mean).powi(2)).sum();
    if ss_tot < f64::EPSILON {
        return 0.0;
    }

    // Build normal equations: A * [a, b, c]^T = rhs
    // where columns are [x², x, 1] and x is normalized to [0, 1].
    let mut s = [0.0f64; 5]; // s[k] = Σ x^k
    let mut r = [0.0f64; 3]; // r[k] = Σ x^k * y
    s[0] = n_f;

    for (i, &y) in values.iter().enumerate() {
        let x = i as f64 / (n - 1).max(1) as f64;
        let x2 = x * x;
        s[1] += x;
        s[2] += x2;
        s[3] += x2 * x;
        s[4] += x2 * x2;
        r[0] += y;
        r[1] += x * y;
        r[2] += x2 * y;
    }

    // Augmented matrix [A | rhs] for Gaussian elimination.
    // Row 0: [s4, s3, s2 | r2]  (x^2 equation)
    // Row 1: [s3, s2, s1 | r1]  (x equation)
    // Row 2: [s2, s1, s0 | r0]  (constant equation)
    let mut m = [
        [s[4], s[3], s[2], r[2]],
        [s[3], s[2], s[1], r[1]],
        [s[2], s[1], s[0], r[0]],
    ];

    // Gaussian elimination with partial pivoting.
    for col in 0..3 {
        // Find pivot.
        let mut max_row = col;
        let mut max_val = m[col][col].abs();
        for row in (col + 1)..3 {
            if m[row][col].abs() > max_val {
                max_val = m[row][col].abs();
                max_row = row;
            }
        }
        if max_val < f64::EPSILON * 1e6 {
            return 0.0; // Singular.
        }
        if max_row != col {
            m.swap(col, max_row);
        }

        // Eliminate below.
        for row in (col + 1)..3 {
            let factor = m[row][col] / m[col][col];
            for j in col..4 {
                m[row][j] -= factor * m[col][j];
            }
        }
    }

    // Back-substitution.
    let mut coeffs = [0.0f64; 3];
    for i in (0..3).rev() {
        if m[i][i].abs() < f64::EPSILON * 1e6 {
            return 0.0;
        }
        let mut sum = m[i][3];
        for j in (i + 1)..3 {
            sum -= m[i][j] * coeffs[j];
        }
        coeffs[i] = sum / m[i][i];
    }

    let (a, b, c) = (coeffs[0], coeffs[1], coeffs[2]);

    let ss_res: f64 = values
        .iter()
        .enumerate()
        .map(|(i, &y)| {
            let x = i as f64 / (n - 1).max(1) as f64;
            let y_pred = a * x * x + b * x + c;
            (y - y_pred).powi(2)
        })
        .sum();

    if !ss_res.is_finite() {
        return 0.0;
    }

    (1.0 - ss_res / ss_tot).clamp(0.0, 1.0)
}

/// Split text into sentences at sentence-terminating punctuation.
fn split_into_sentences(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut current = String::new();

    for ch in text.chars() {
        current.push(ch);
        if SENTENCE_TERMINATORS.contains(&ch) {
            let trimmed = current.trim().to_string();
            if !trimmed.is_empty() {
                sentences.push(trimmed);
            }
            current.clear();
        }
    }

    // Trailing text without terminator.
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        sentences.push(trimmed);
    }

    sentences
}

// ---------------------------------------------------------------------------
// Document-scale: Structural boundary pause concentration
// ---------------------------------------------------------------------------

/// Compute mutual information between deep pauses and structural boundaries.
///
/// Returns a score in [0, 1]: high = pauses concentrate at boundaries (cognitive),
/// low = pauses are structurally arbitrary (transcriptive).
fn compute_structural_pause_concentration(
    document_text: &str,
    samples: &[SimpleJitterSample],
) -> Option<f64> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }

    let total_chars: usize = document_text.chars().count();
    if total_chars < 50 {
        return None;
    }

    // Find structural boundary positions as fractions of document length.
    let mut boundary_positions: Vec<f64> = Vec::new();
    let mut char_idx = 0usize;
    let mut prev_char = ' ';

    for ch in document_text.chars() {
        char_idx += 1;
        let pos = char_idx as f64 / total_chars as f64;

        // Sentence boundary.
        if SENTENCE_TERMINATORS.contains(&prev_char) && (ch == ' ' || ch == '\n') {
            boundary_positions.push(pos);
        }
        prev_char = ch;
    }

    // Find paragraph boundaries.
    for (i, _) in document_text.match_indices(PARAGRAPH_BREAK) {
        let pos = i as f64 / document_text.len().max(1) as f64;
        boundary_positions.push(pos);
    }

    boundary_positions.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    boundary_positions.dedup();

    if boundary_positions.is_empty() {
        return None;
    }

    // Find deep pause positions as fractions of the sample stream.
    let deep_pause_positions: Vec<f64> = samples
        .iter()
        .enumerate()
        .filter(|(_, s)| s.duration_since_last_ns >= STRUCTURAL_PAUSE_NS)
        .map(|(i, _)| i as f64 / samples.len() as f64)
        .collect();

    if deep_pause_positions.is_empty() {
        // No deep pauses at all — ambiguous, return neutral.
        return Some(0.5);
    }

    // For each deep pause, compute minimum distance to any structural boundary.
    let mut total_proximity = 0.0f64;
    for &pause_pos in &deep_pause_positions {
        let min_dist = boundary_positions
            .iter()
            .map(|&bp| (pause_pos - bp).abs())
            .fold(f64::MAX, f64::min);
        // Convert distance to proximity: 1.0 at boundary, 0.0 far away.
        // Use a Gaussian-like decay with sigma = 0.05 (5% of document).
        total_proximity += (-min_dist.powi(2) / (2.0 * 0.05 * 0.05)).exp();
    }

    let mean_proximity = total_proximity / deep_pause_positions.len() as f64;

    Some(mean_proximity.clamp(0.0, 1.0))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Cognitive Load-Timing Entanglement metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CognitiveLoadMetrics {
    /// Spearman rho between IKI and word surprisal.
    /// Cognitive: 0.3-0.6 (timing tracks difficulty). Transcriptive: ~0.
    pub iki_surprisal_rho: f64,

    /// Mean R² of quadratic fit to per-sentence IKI velocity arcs.
    /// Cognitive: >0.3 (planning-execution arc). Transcriptive: <0.1.
    pub sentence_arc_r_squared: f64,

    /// Structural boundary pause concentration.
    /// Cognitive: >0.6 (pauses at sentence/paragraph boundaries).
    /// Transcriptive: <0.3 (pauses at arbitrary positions).
    pub structural_pause_concentration: f64,

    /// Composite score: 0.0 = transcriptive, 1.0 = cognitive.
    pub composite_score: f64,

    /// Number of deep pauses (>3s) analyzed.
    pub deep_pause_count: usize,

    /// Number of structural boundaries identified.
    pub boundary_count: usize,

    /// Number of words with surprisal data.
    pub word_count: usize,

    /// Number of sentences analyzed for velocity arcs.
    pub sentence_count: usize,
}

/// Analyze cognitive load-timing entanglement.
///
/// Requires document text and jitter samples. Returns `None` if insufficient data.
pub fn analyze_cognitive_load(
    document_text: Option<&str>,
    samples: &[SimpleJitterSample],
) -> Option<CognitiveLoadMetrics> {
    let text = document_text?;
    if samples.len() < MIN_SAMPLES || text.len() < 50 {
        return None;
    }

    let iki_surprisal_rho = compute_iki_surprisal_correlation(text, samples)
        .filter(|v| v.is_finite())
        .unwrap_or(0.0);
    let sentence_arc_r_squared = compute_sentence_velocity_arcs(text, samples)
        .filter(|v| v.is_finite())
        .unwrap_or(0.0);
    let structural_pause_concentration = compute_structural_pause_concentration(text, samples)
        .filter(|v| v.is_finite())
        .unwrap_or(0.5);

    let deep_pause_count = samples
        .iter()
        .filter(|s| s.duration_since_last_ns >= STRUCTURAL_PAUSE_NS)
        .count();
    let boundary_count = {
        let mut count = 0usize;
        let mut prev = ' ';
        for ch in text.chars() {
            if SENTENCE_TERMINATORS.contains(&prev) && (ch == ' ' || ch == '\n') {
                count += 1;
            }
            prev = ch;
        }
        count += text.matches(PARAGRAPH_BREAK).count();
        count
    };
    let word_count = compute_word_surprisals(text).len();
    let sentence_count = split_into_sentences(text).len();

    // Composite score: weighted combination of three scales.
    // Word-scale (surprisal correlation) is the strongest signal.
    let word_score = ((iki_surprisal_rho + 0.1) / 0.7).clamp(0.0, 1.0); // -0.1→0, 0.6→1
    let clause_score = (sentence_arc_r_squared / 0.4).clamp(0.0, 1.0); // 0→0, 0.4→1
    let doc_score = structural_pause_concentration; // Already [0, 1]

    let composite_score = 0.50 * word_score + 0.30 * clause_score + 0.20 * doc_score;

    Some(CognitiveLoadMetrics {
        iki_surprisal_rho,
        sentence_arc_r_squared,
        structural_pause_concentration,
        composite_score,
        deep_pause_count,
        boundary_count,
        word_count,
        sentence_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_samples(ikis_ms: &[u64]) -> Vec<SimpleJitterSample> {
        let mut ts = 0i64;
        ikis_ms
            .iter()
            .map(|&iki| {
                let iki_ns = iki * 1_000_000;
                ts += iki_ns as i64;
                SimpleJitterSample {
                    timestamp_ns: ts,
                    duration_since_last_ns: iki_ns,
                    ..Default::default()
                }
            })
            .collect()
    }

    #[test]
    fn test_word_surprisal_common() {
        assert!(word_surprisal("the") < 2.0);
        assert!(word_surprisal("antidisestablishmentarianism") > 8.0);
    }

    #[test]
    fn test_spearman_perfect_positive() {
        let xs = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ys = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let rho = spearman_correlation(&xs, &ys);
        assert!((rho - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_spearman_perfect_negative() {
        let xs = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ys = vec![50.0, 40.0, 30.0, 20.0, 10.0];
        let rho = spearman_correlation(&xs, &ys);
        assert!((rho + 1.0).abs() < 0.01);
    }

    #[test]
    fn test_quadratic_r_squared_perfect() {
        // Perfect quadratic: y = x^2
        let values: Vec<f64> = (0..10).map(|i| (i as f64).powi(2)).collect();
        let r_sq = quadratic_r_squared(&values);
        assert!(r_sq > 0.99, "R² should be ~1.0, got {}", r_sq);
    }

    #[test]
    fn test_quadratic_r_squared_linear() {
        // Linear data: y = x. Quadratic should still fit well (a≈0).
        let values: Vec<f64> = (0..10).map(|i| i as f64).collect();
        let r_sq = quadratic_r_squared(&values);
        assert!(r_sq > 0.99, "R² should be ~1.0 for linear, got {}", r_sq);
    }

    #[test]
    fn test_sentence_splitting() {
        let text = "Hello world. This is a test! Does it work? Yes it does.";
        let sentences = split_into_sentences(text);
        assert_eq!(sentences.len(), 4);
    }

    #[test]
    fn test_cognitive_load_insufficient_data() {
        let samples = make_samples(&[100; 10]);
        let result = analyze_cognitive_load(Some("Short"), &samples);
        assert!(result.is_none());
    }

    #[test]
    fn test_cognitive_load_no_text() {
        let samples = make_samples(&[100; 50]);
        let result = analyze_cognitive_load(None, &samples);
        assert!(result.is_none());
    }

    #[test]
    fn test_cognitive_load_with_sufficient_data() {
        // Generate a document with enough words.
        let text = "The quick brown fox jumped over the lazy dog. \
                    She was running through the antidisestablishmentarian countryside. \
                    A beautiful morning greeted the weary travelers. \
                    The extraordinary circumstances required immediate attention. \
                    Simple words came first but then the sesquipedalian vocabulary emerged. \
                    He wrote diligently through the afternoon sun. \
                    The cat sat on the mat and purred contentedly. \
                    We should investigate the phenomenological aspects carefully.";

        // Create samples with varied IKI (some correlation with word difficulty).
        let ikis: Vec<u64> = (0..80)
            .map(|i| {
                let base = 150u64;
                let variation = ((i * 37 + 13) % 200) as u64;
                base + variation
            })
            .collect();
        let samples = make_samples(&ikis);

        let result = analyze_cognitive_load(Some(text), &samples);
        assert!(result.is_some());
        let metrics = result.unwrap();
        assert!(metrics.word_count > 10);
        assert!(metrics.sentence_count >= 3);
        assert!(metrics.composite_score >= 0.0 && metrics.composite_score <= 1.0);
    }

    #[test]
    fn test_structural_pause_concentration() {
        let text = "First sentence here. Second sentence follows. Third one now.";
        // Place a deep pause exactly at sentence boundaries.
        let mut ikis: Vec<u64> = vec![100; 50];
        // Insert deep pauses near positions that map to sentence boundaries.
        ikis[15] = 4000; // ~30% through → near first sentence boundary
        ikis[30] = 5000; // ~60% through → near second boundary
        let samples = make_samples(&ikis);

        let result = compute_structural_pause_concentration(text, &samples);
        assert!(result.is_some());
        // Pauses at boundaries should yield high concentration.
        assert!(result.unwrap() > 0.3);
    }
}
