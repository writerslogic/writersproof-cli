// SPDX-License-Identifier: Apache-2.0

//! Cognitive vs transcriptive classification using content-aware signals.
//!
//! Two classifiers that require text content alongside timing data:
//! - **Lexical Retrieval Delay (LRD)**: Correlation between word frequency and
//!   pre-word pause duration. Cognitive writers pause longer before rare words;
//!   transcribers don't (they're reading, not retrieving).
//! - **Non-Append Ratio**: Proportion of edits that aren't simple appends.
//!   Cognitive writers jump around, insert, and delete; transcribers type linearly.

use serde::{Deserialize, Serialize};

/// A word boundary event with timing and frequency data.
#[derive(Debug, Clone)]
pub struct WordBoundaryEvent {
    /// Pause duration before the word started (ms).
    pub pre_word_pause_ms: u32,
    /// Frequency tier of the word (1 = top 100, 2 = 101-1000, 3 = 1001-5000, 4 = rare).
    pub frequency_tier: u8,
}

/// Edit operation type for non-append ratio computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditOp {
    /// Character appended at end of document.
    Append,
    /// Character inserted at non-end position.
    Insert,
    /// Character(s) deleted.
    Delete,
    /// Cursor repositioned without editing.
    CursorJump,
}

/// Combined cognitive classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveContentMetrics {
    /// Pearson correlation between log(word_rank) and pre-word pause.
    /// Cognitive: r > 0.25 (rare words → longer pauses).
    /// Transcriptive: r ≈ 0 (pause independent of word rarity).
    pub lrd_correlation: f64,
    /// Proportion of edit operations that are not simple appends.
    /// Cognitive: > 0.15 (inserts, deletes, jumps).
    /// Transcriptive: < 0.03 (almost pure append stream).
    pub non_append_ratio: f64,
    /// Deletion semantic score: average length of deleted spans.
    /// Cognitive: > 3.0 (whole words/phrases deleted — changed mind).
    /// Transcriptive: < 2.0 (single-char typo corrections).
    pub mean_deletion_length: f64,
    /// Combined cognitive probability [0, 1].
    pub cognitive_probability: f64,
    /// Number of word boundaries analyzed for LRD.
    pub word_boundary_count: usize,
    /// Total edit operations analyzed.
    pub total_edit_ops: usize,
}

/// Compute Lexical Retrieval Delay correlation.
///
/// Measures Pearson r between frequency_tier (proxy for log word rank) and
/// pre-word pause. Requires at least 20 word boundary events.
pub fn compute_lrd_correlation(events: &[WordBoundaryEvent]) -> Option<f64> {
    if events.len() < 20 {
        return None;
    }

    // Filter out extreme pauses (> 10s = not typing, likely distraction).
    let filtered: Vec<&WordBoundaryEvent> = events
        .iter()
        .filter(|e| e.pre_word_pause_ms > 0 && e.pre_word_pause_ms < 10_000)
        .collect();

    if filtered.len() < 15 {
        return None;
    }

    let n = filtered.len() as f64;
    let mut sum_x = 0.0f64;
    let mut sum_y = 0.0f64;
    let mut sum_xy = 0.0f64;
    let mut sum_x2 = 0.0f64;
    let mut sum_y2 = 0.0f64;

    for event in &filtered {
        let x = event.frequency_tier as f64; // 1-4 (proxy for log rank)
        let y = event.pre_word_pause_ms as f64;
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
        sum_y2 += y * y;
    }

    let numerator = n * sum_xy - sum_x * sum_y;
    let denom_x = n * sum_x2 - sum_x * sum_x;
    let denom_y = n * sum_y2 - sum_y * sum_y;
    let denominator = (denom_x * denom_y).sqrt();

    if denominator < 1e-10 {
        return Some(0.0); // No variance in one or both variables.
    }

    Some(numerator / denominator)
}

/// Compute non-append ratio and mean deletion length from edit operations.
///
/// Returns (non_append_ratio, mean_deletion_length).
pub fn compute_edit_topology(ops: &[EditOp]) -> (f64, f64) {
    if ops.is_empty() {
        return (0.0, 0.0);
    }

    let total = ops.len() as f64;
    let non_append = ops.iter().filter(|&&op| op != EditOp::Append).count() as f64;

    // Compute mean deletion run length.
    let mut deletion_lengths: Vec<usize> = Vec::new();
    let mut current_run = 0usize;
    for &op in ops {
        if op == EditOp::Delete {
            current_run += 1;
        } else {
            if current_run > 0 {
                deletion_lengths.push(current_run);
            }
            current_run = 0;
        }
    }
    if current_run > 0 {
        deletion_lengths.push(current_run);
    }

    let mean_del_len = if deletion_lengths.is_empty() {
        0.0
    } else {
        deletion_lengths.iter().sum::<usize>() as f64 / deletion_lengths.len() as f64
    };

    (non_append / total, mean_del_len)
}

/// Compute combined cognitive content metrics from word boundaries and edit ops.
pub fn analyze_cognitive_content(
    word_events: &[WordBoundaryEvent],
    edit_ops: &[EditOp],
) -> CognitiveContentMetrics {
    let lrd = compute_lrd_correlation(word_events).unwrap_or(0.0);
    let (non_append, mean_del) = compute_edit_topology(edit_ops);

    let lrd_prob = cpoe_jitter::sigmoid(lrd, 10.0, 0.15);
    let nar_prob = cpoe_jitter::sigmoid(non_append, 30.0, 0.08);
    let del_prob = cpoe_jitter::sigmoid(mean_del, 1.5, 2.5);

    // Weight: LRD is strongest signal, non-append is structural, deletion confirms.
    let combined = if word_events.len() >= 20 && edit_ops.len() >= 50 {
        lrd_prob * 0.45 + nar_prob * 0.35 + del_prob * 0.20
    } else if word_events.len() >= 20 {
        lrd_prob * 0.7 + del_prob * 0.3
    } else if edit_ops.len() >= 50 {
        nar_prob * 0.6 + del_prob * 0.4
    } else {
        0.5 // Insufficient data, neutral.
    };

    CognitiveContentMetrics {
        lrd_correlation: lrd,
        non_append_ratio: non_append,
        mean_deletion_length: mean_del,
        cognitive_probability: combined,
        word_boundary_count: word_events.len(),
        total_edit_ops: edit_ops.len(),
    }
}

/// Classify a word into frequency tier using COCA-based lookup table.
/// Tier 1: ranks 1-100 (~50% of running text).
/// Tier 2: ranks 101-500 (~30% of text).
/// Tier 3: ranks 501-2000 (~15% of text).
/// Tier 4: not in top 2000 (rare/technical/literary).
pub fn word_frequency_tier(word: &str) -> u8 {
    super::word_frequency::lookup_tier(word)
}

// ---------------------------------------------------------------------------
// Error Fingerprinting
// ---------------------------------------------------------------------------

/// Type of correction observed during editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrectionType {
    /// Single character typo (backspace + retype). Motor error.
    SingleCharTypo,
    /// Multiple characters deleted and retyped with different content. Semantic revision.
    SemanticRevision,
    /// Word-level deletion (whole word removed). Cognitive restructuring.
    WordDeletion,
    /// Characters deleted match a visually similar pattern (rn→m, cl→d). Reading error.
    VisualConfusion,
    /// Skipped content then backfilled. Buffer underrun from copying.
    BackfillInsertion,
}

/// Correction event captured during editing.
#[derive(Debug, Clone)]
pub struct CorrectionEvent {
    pub correction_type: CorrectionType,
    /// Number of characters involved in the correction.
    pub char_count: usize,
}

/// Error fingerprint analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorFingerprint {
    /// Proportion of corrections that are semantic (word+ deletions, restructuring).
    /// Cognitive: > 0.4, Transcriptive: < 0.15.
    pub semantic_ratio: f64,
    /// Proportion that are single-char typos.
    /// Both modes produce these; not discriminative alone.
    pub typo_ratio: f64,
    /// Proportion that are visual confusion or backfill.
    /// Cognitive: < 0.05, Transcriptive: > 0.15.
    pub visual_error_ratio: f64,
    /// Mean characters per correction. Cognitive: > 4, Transcriptive: < 2.
    pub mean_correction_size: f64,
    /// Cognitive probability from error patterns [0, 1].
    pub cognitive_probability: f64,
    pub total_corrections: usize,
}

/// Analyze correction patterns to distinguish cognitive vs transcriptive errors.
///
/// Requires at least 5 corrections for meaningful analysis.
pub fn analyze_error_fingerprint(corrections: &[CorrectionEvent]) -> Option<ErrorFingerprint> {
    if corrections.len() < 5 {
        return None;
    }

    let total = corrections.len() as f64;
    let semantic_count = corrections
        .iter()
        .filter(|c| {
            matches!(
                c.correction_type,
                CorrectionType::SemanticRevision | CorrectionType::WordDeletion
            )
        })
        .count() as f64;
    let visual_count = corrections
        .iter()
        .filter(|c| {
            matches!(
                c.correction_type,
                CorrectionType::VisualConfusion | CorrectionType::BackfillInsertion
            )
        })
        .count() as f64;
    let typo_count = corrections
        .iter()
        .filter(|c| c.correction_type == CorrectionType::SingleCharTypo)
        .count() as f64;

    let semantic_ratio = semantic_count / total;
    let visual_error_ratio = visual_count / total;
    let typo_ratio = typo_count / total;
    let mean_correction_size = corrections.iter().map(|c| c.char_count as f64).sum::<f64>() / total;

    let semantic_score = cpoe_jitter::sigmoid(semantic_ratio, 8.0, 0.25);
    let size_score = cpoe_jitter::sigmoid(mean_correction_size, 1.0, 3.0);
    let visual_penalty = 1.0 - cpoe_jitter::sigmoid(visual_error_ratio, 10.0, 0.1);

    let cognitive_probability = semantic_score * 0.45 + size_score * 0.30 + visual_penalty * 0.25;

    Some(ErrorFingerprint {
        semantic_ratio,
        typo_ratio,
        visual_error_ratio,
        mean_correction_size,
        cognitive_probability,
        total_corrections: corrections.len(),
    })
}

// ---------------------------------------------------------------------------
// Personal Baseline Model
// ---------------------------------------------------------------------------

/// Per-writer baseline statistics accumulated over multiple sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalBaseline {
    /// Mean sentence initiation ratio for this writer.
    pub mean_sid_ratio: f64,
    /// Standard deviation of SID ratio across sessions.
    pub std_sid_ratio: f64,
    /// Mean bigram fluency ratio.
    pub mean_bigram_fluency: f64,
    /// Mean LRD correlation.
    pub mean_lrd_correlation: f64,
    /// Mean non-append ratio.
    pub mean_non_append_ratio: f64,
    /// Number of sessions contributing to this baseline.
    pub session_count: u32,
}

/// Compare a session's metrics against a personal baseline.
///
/// Returns a deviation score [0, 1] where 0 = perfectly consistent with baseline,
/// 1 = extreme deviation (possible impostor or mode switch).
pub fn compute_baseline_deviation(
    baseline: &PersonalBaseline,
    temporal: Option<&cpoe_jitter::cognitive::CognitiveTemporalMetrics>,
    content: Option<&CognitiveContentMetrics>,
) -> f64 {
    if baseline.session_count < 3 {
        return 0.0; // Insufficient baseline data.
    }

    let mut deviations: Vec<f64> = Vec::new();

    if let Some(t) = temporal {
        // How many standard deviations away from personal baseline?
        if baseline.std_sid_ratio > 0.1 {
            let z_sid = ((t.sentence_initiation_ratio - baseline.mean_sid_ratio)
                / baseline.std_sid_ratio)
                .abs();
            deviations.push(z_sid);
        }
        let z_bigram = (t.bigram_fluency_ratio - baseline.mean_bigram_fluency).abs();
        deviations.push(z_bigram);
    }

    if let Some(c) = content {
        let z_lrd = (c.lrd_correlation - baseline.mean_lrd_correlation).abs() * 3.0;
        let z_nar = (c.non_append_ratio - baseline.mean_non_append_ratio).abs() * 5.0;
        deviations.push(z_lrd);
        deviations.push(z_nar);
    }

    if deviations.is_empty() {
        return 0.0;
    }

    // Max deviation across all metrics (most anomalous dimension).
    let max_z = deviations.iter().cloned().fold(0.0f64, f64::max);

    // Map z-score to [0, 1]: z < 1.5 = normal, z > 3.0 = extreme.
    cpoe_jitter::sigmoid(max_z, 2.0, 2.0)
}

// ---------------------------------------------------------------------------
// Unified Writing Mode Classifier
// ---------------------------------------------------------------------------

/// Final verdict from the unified classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WritingMode {
    /// Strong evidence of original cognitive composition.
    Cognitive,
    /// Strong evidence of transcription/copying.
    Transcriptive,
    /// Mixed or insufficient evidence to classify.
    Indeterminate,
}

/// Complete classification result combining all signal layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WritingModeVerdict {
    pub mode: WritingMode,
    /// Overall cognitive probability [0, 1] from all available signals.
    pub cognitive_score: f64,
    /// Confidence in the verdict [0, 1] based on data sufficiency.
    pub confidence: f64,
    /// Joint inconsistency score [0, 1]. High values indicate selective spoofing:
    /// one signal layer was faked but others weren't kept consistent.
    pub spoofing_indicator: f64,
    /// Which signal layers contributed to the verdict.
    pub layers_used: Vec<String>,
}

/// Unified classifier combining temporal, content, and structural signals.
///
/// Takes outputs from all three analysis layers and produces a single verdict.
/// Requires at least 2 of 3 layers to have usable data.
pub fn classify_writing_mode(
    temporal: Option<&cpoe_jitter::cognitive::CognitiveTemporalMetrics>,
    content: Option<&CognitiveContentMetrics>,
    transcription: Option<&super::transcription::TranscriptionAnalysis>,
) -> WritingModeVerdict {
    let mut weighted_sum = 0.0f64;
    let mut total_weight = 0.0f64;
    let mut layers = Vec::new();

    // Layer 1: Temporal signals (sentence initiation + bigram fluency + IKI modality).
    // Highest weight: hardest to fake, most granular.
    if let Some(t) = temporal {
        weighted_sum += t.cognitive_probability * 0.45;
        total_weight += 0.45;
        layers.push("temporal".into());
    }

    // Layer 2: Content signals (LRD + non-append ratio + deletion topology).
    // Second weight: requires realistic revision patterns.
    if let Some(c) = content {
        weighted_sum += c.cognitive_probability * 0.35;
        total_weight += 0.35;
        layers.push("content".into());
    }

    // Layer 3: Structural signals (existing TranscriptionDetector: linearity, revision density).
    // Third weight: coarsest signal, easiest to game.
    if let Some(tr) = transcription {
        // Invert: TranscriptionAnalysis.is_transcription → low cognitive score.
        let structural_score = if tr.is_transcription { 0.1 } else { 0.85 };
        weighted_sum += structural_score * 0.20;
        total_weight += 0.20;
        layers.push("structural".into());
    }

    if total_weight < 0.3 || layers.len() < 2 {
        return WritingModeVerdict {
            mode: WritingMode::Indeterminate,
            cognitive_score: 0.5,
            confidence: 0.0,
            spoofing_indicator: 0.0,
            layers_used: layers,
        };
    }

    let cognitive_score = weighted_sum / total_weight;

    // Joint consistency check: detect spoofing via signal disagreement.
    // If signals strongly disagree (one says cognitive, another says transcriptive),
    // that's harder to produce naturally than through selective faking.
    let spoofing_penalty = compute_spoofing_penalty(temporal, content, transcription);
    let confidence =
        ((total_weight / 1.0).min(1.0) * (layers.len() as f64 / 3.0)) * (1.0 - spoofing_penalty);

    let mode = if spoofing_penalty > 0.5 {
        // Strong disagreement between signals: likely spoofing attempt.
        WritingMode::Indeterminate
    } else if cognitive_score > 0.65 && confidence > 0.4 {
        WritingMode::Cognitive
    } else if cognitive_score < 0.35 && confidence > 0.4 {
        WritingMode::Transcriptive
    } else {
        WritingMode::Indeterminate
    };

    WritingModeVerdict {
        mode,
        cognitive_score,
        confidence,
        spoofing_indicator: spoofing_penalty,
        layers_used: layers,
    }
}

/// Detect joint inconsistency between signal layers.
///
/// A skilled forger can fake one signal (e.g., add artificial pauses before sentences)
/// but maintaining consistency across ALL signals simultaneously is exponentially harder.
/// Signal disagreement indicates selective spoofing.
///
/// Returns a penalty in [0, 1]: 0 = consistent, 1 = strong disagreement.
fn compute_spoofing_penalty(
    temporal: Option<&cpoe_jitter::cognitive::CognitiveTemporalMetrics>,
    content: Option<&CognitiveContentMetrics>,
    transcription: Option<&super::transcription::TranscriptionAnalysis>,
) -> f64 {
    let mut scores: Vec<f64> = Vec::new();

    if let Some(t) = temporal {
        scores.push(t.cognitive_probability);
    }
    if let Some(c) = content {
        scores.push(c.cognitive_probability);
    }
    if let Some(tr) = transcription {
        scores.push(if tr.is_transcription { 0.1 } else { 0.85 });
    }

    if scores.len() < 2 {
        return 0.0;
    }

    // Compute max disagreement between any two layers.
    let mut max_disagreement = 0.0f64;
    for i in 0..scores.len() {
        for j in (i + 1)..scores.len() {
            let disagreement = (scores[i] - scores[j]).abs();
            if disagreement > max_disagreement {
                max_disagreement = disagreement;
            }
        }
    }

    // Disagreement > 0.5 is suspicious. > 0.7 is almost certainly spoofing.
    // Map: 0.0-0.4 → 0, 0.4-0.8 → 0-1 (sigmoid).
    if max_disagreement < 0.4 {
        0.0
    } else {
        cpoe_jitter::sigmoid(max_disagreement, 8.0, 0.6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lrd_cognitive_pattern() {
        // Cognitive: rare words (tier 4) get long pauses, common (tier 1) get short.
        let events: Vec<WordBoundaryEvent> = (0..60)
            .map(|i| {
                let tier = (i % 4) as u8 + 1;
                let pause = match tier {
                    1 => 150, // Common: short pause
                    2 => 250, // Medium: moderate
                    3 => 400, // Uncommon: longer
                    _ => 700, // Rare: long retrieval delay
                };
                WordBoundaryEvent {
                    pre_word_pause_ms: pause,
                    frequency_tier: tier,
                }
            })
            .collect();

        let r = compute_lrd_correlation(&events).unwrap();
        assert!(
            r > 0.8,
            "Expected high correlation for cognitive pattern, got {r}"
        );
    }

    #[test]
    fn test_lrd_transcriptive_pattern() {
        // Transcriptive: uniform pauses regardless of word frequency.
        let events: Vec<WordBoundaryEvent> = (0..60)
            .map(|i| WordBoundaryEvent {
                pre_word_pause_ms: 180 + (i as u32 % 20), // ~uniform
                frequency_tier: (i % 4) as u8 + 1,
            })
            .collect();

        let r = compute_lrd_correlation(&events).unwrap();
        assert!(
            r.abs() < 0.2,
            "Expected low correlation for transcription, got {r}"
        );
    }

    #[test]
    fn test_non_append_cognitive() {
        // Cognitive: lots of inserts, deletes, jumps.
        let ops = vec![
            EditOp::Append,
            EditOp::Append,
            EditOp::Append,
            EditOp::Delete,
            EditOp::Delete,
            EditOp::Delete,
            EditOp::Delete, // 4-char deletion
            EditOp::Insert,
            EditOp::Insert,
            EditOp::Append,
            EditOp::Append,
            EditOp::CursorJump,
            EditOp::Insert,
            EditOp::Insert,
            EditOp::Insert,
            EditOp::Append,
            EditOp::Append,
            EditOp::Append,
            EditOp::Append,
            EditOp::Delete,
            EditOp::Delete,
            EditOp::Delete, // 3-char deletion
        ];
        let (ratio, mean_del) = compute_edit_topology(&ops);
        assert!(ratio > 0.4, "ratio={ratio}");
        assert!(mean_del > 3.0, "mean_del={mean_del}");
    }

    #[test]
    fn test_non_append_transcriptive() {
        // Transcriptive: almost all appends, occasional single-char delete.
        let mut ops = vec![EditOp::Append; 100];
        ops[30] = EditOp::Delete;
        ops[60] = EditOp::Delete;
        let (ratio, mean_del) = compute_edit_topology(&ops);
        assert!(ratio < 0.03, "ratio={ratio}");
        assert!(mean_del <= 1.0, "mean_del={mean_del}");
    }

    #[test]
    fn test_word_frequency_tiers() {
        assert_eq!(word_frequency_tier("the"), 1);
        assert_eq!(word_frequency_tier("and"), 1);
        assert_eq!(word_frequency_tier("family"), 2);
        assert_eq!(word_frequency_tier("technology"), 3);
        assert_eq!(word_frequency_tier("conflagration"), 4);
        assert_eq!(word_frequency_tier("sesquipedalian"), 4);
    }

    #[test]
    fn test_combined_cognitive() {
        let word_events: Vec<WordBoundaryEvent> = (0..40)
            .map(|i| {
                let tier = (i % 4) as u8 + 1;
                WordBoundaryEvent {
                    pre_word_pause_ms: 100 + tier as u32 * 150,
                    frequency_tier: tier,
                }
            })
            .collect();

        let mut edit_ops = vec![EditOp::Append; 50];
        // Add cognitive edits: insertions and multi-char deletions.
        for i in (10..50).step_by(5) {
            edit_ops[i] = EditOp::Delete;
            if i + 1 < 50 {
                edit_ops[i + 1] = EditOp::Delete;
            }
            if i + 2 < 50 {
                edit_ops[i + 2] = EditOp::Delete;
            }
        }
        edit_ops.push(EditOp::Insert);
        edit_ops.push(EditOp::Insert);
        edit_ops.push(EditOp::CursorJump);

        let metrics = analyze_cognitive_content(&word_events, &edit_ops);
        assert!(
            metrics.cognitive_probability > 0.6,
            "prob={}",
            metrics.cognitive_probability
        );
    }

    #[test]
    fn test_combined_transcriptive() {
        let word_events: Vec<WordBoundaryEvent> = (0..40)
            .map(|i| WordBoundaryEvent {
                pre_word_pause_ms: 200,
                frequency_tier: (i % 4) as u8 + 1,
            })
            .collect();

        let edit_ops = vec![EditOp::Append; 100];

        let metrics = analyze_cognitive_content(&word_events, &edit_ops);
        assert!(
            metrics.cognitive_probability < 0.4,
            "prob={}",
            metrics.cognitive_probability
        );
    }

    #[test]
    fn test_unified_cognitive_verdict() {
        use cpoe_jitter::cognitive::CognitiveTemporalMetrics;

        let temporal = CognitiveTemporalMetrics {
            sentence_initiation_ratio: 12.0,
            sentence_initiation_variance: 25.0,
            bigram_fluency_ratio: 2.8,
            iki_modality_score: 0.85,
            cognitive_probability: 0.82,
            sentence_count: 5,
            bigram_pairs_analyzed: 100,
        };
        let content = CognitiveContentMetrics {
            lrd_correlation: 0.45,
            non_append_ratio: 0.22,
            mean_deletion_length: 4.5,
            cognitive_probability: 0.78,
            word_boundary_count: 40,
            total_edit_ops: 200,
        };

        let verdict = classify_writing_mode(Some(&temporal), Some(&content), None);
        assert_eq!(verdict.mode, WritingMode::Cognitive);
        assert!(
            verdict.cognitive_score > 0.7,
            "score={}",
            verdict.cognitive_score
        );
        assert_eq!(verdict.layers_used.len(), 2);
    }

    #[test]
    fn test_unified_transcriptive_verdict() {
        use super::super::transcription::TranscriptionAnalysis;
        use cpoe_jitter::cognitive::CognitiveTemporalMetrics;

        let temporal = CognitiveTemporalMetrics {
            sentence_initiation_ratio: 2.5,
            sentence_initiation_variance: 1.0,
            bigram_fluency_ratio: 1.2,
            iki_modality_score: 0.15,
            cognitive_probability: 0.12,
            sentence_count: 4,
            bigram_pairs_analyzed: 80,
        };
        let transcription = TranscriptionAnalysis {
            linearity_score: 0.96,
            revision_density: 1.2,
            nonlinearity_index: 0.5,
            avg_burst_length: 25.0,
            is_transcription: true,
            explanation: String::new(),
        };

        let verdict = classify_writing_mode(Some(&temporal), None, Some(&transcription));
        assert_eq!(verdict.mode, WritingMode::Transcriptive);
        assert!(
            verdict.cognitive_score < 0.3,
            "score={}",
            verdict.cognitive_score
        );
    }

    #[test]
    fn test_unified_insufficient_data() {
        let verdict = classify_writing_mode(None, None, None);
        assert_eq!(verdict.mode, WritingMode::Indeterminate);
        assert_eq!(verdict.confidence, 0.0);
    }

    #[test]
    fn test_spoofing_detected() {
        use super::super::transcription::TranscriptionAnalysis;
        use cpoe_jitter::cognitive::CognitiveTemporalMetrics;

        // Temporal says cognitive (faked pauses) but structural says transcriptive.
        let temporal = CognitiveTemporalMetrics {
            sentence_initiation_ratio: 15.0,
            sentence_initiation_variance: 30.0,
            bigram_fluency_ratio: 1.1, // But bigrams don't match (uniform speed)
            iki_modality_score: 0.3,   // And distribution is unimodal
            cognitive_probability: 0.85, // Faked SID dominates
            sentence_count: 5,
            bigram_pairs_analyzed: 100,
        };
        let transcription = TranscriptionAnalysis {
            linearity_score: 0.97,
            revision_density: 0.8,
            nonlinearity_index: 0.2,
            avg_burst_length: 30.0,
            is_transcription: true,
            explanation: String::new(),
        };

        let verdict = classify_writing_mode(Some(&temporal), None, Some(&transcription));
        // Should detect disagreement (temporal=0.85, structural=0.1).
        assert!(
            verdict.spoofing_indicator > 0.3,
            "spoofing={}",
            verdict.spoofing_indicator
        );
    }

    #[test]
    fn test_error_fingerprint_cognitive() {
        let corrections = vec![
            CorrectionEvent {
                correction_type: CorrectionType::WordDeletion,
                char_count: 7,
            },
            CorrectionEvent {
                correction_type: CorrectionType::SemanticRevision,
                char_count: 12,
            },
            CorrectionEvent {
                correction_type: CorrectionType::SingleCharTypo,
                char_count: 1,
            },
            CorrectionEvent {
                correction_type: CorrectionType::SemanticRevision,
                char_count: 8,
            },
            CorrectionEvent {
                correction_type: CorrectionType::WordDeletion,
                char_count: 5,
            },
            CorrectionEvent {
                correction_type: CorrectionType::SingleCharTypo,
                char_count: 1,
            },
            CorrectionEvent {
                correction_type: CorrectionType::SemanticRevision,
                char_count: 15,
            },
        ];
        let fp = analyze_error_fingerprint(&corrections).unwrap();
        assert!(fp.semantic_ratio > 0.5, "semantic={}", fp.semantic_ratio);
        assert!(
            fp.mean_correction_size > 4.0,
            "size={}",
            fp.mean_correction_size
        );
        assert!(
            fp.cognitive_probability > 0.6,
            "prob={}",
            fp.cognitive_probability
        );
    }

    #[test]
    fn test_error_fingerprint_transcriptive() {
        let corrections = vec![
            CorrectionEvent {
                correction_type: CorrectionType::SingleCharTypo,
                char_count: 1,
            },
            CorrectionEvent {
                correction_type: CorrectionType::SingleCharTypo,
                char_count: 1,
            },
            CorrectionEvent {
                correction_type: CorrectionType::VisualConfusion,
                char_count: 2,
            },
            CorrectionEvent {
                correction_type: CorrectionType::SingleCharTypo,
                char_count: 1,
            },
            CorrectionEvent {
                correction_type: CorrectionType::BackfillInsertion,
                char_count: 3,
            },
            CorrectionEvent {
                correction_type: CorrectionType::SingleCharTypo,
                char_count: 1,
            },
        ];
        let fp = analyze_error_fingerprint(&corrections).unwrap();
        assert!(
            fp.visual_error_ratio > 0.2,
            "visual={}",
            fp.visual_error_ratio
        );
        assert!(
            fp.mean_correction_size < 2.0,
            "size={}",
            fp.mean_correction_size
        );
        assert!(
            fp.cognitive_probability < 0.4,
            "prob={}",
            fp.cognitive_probability
        );
    }

    #[test]
    fn test_baseline_deviation_normal() {
        use cpoe_jitter::cognitive::CognitiveTemporalMetrics;

        let baseline = PersonalBaseline {
            mean_sid_ratio: 10.0,
            std_sid_ratio: 3.0,
            mean_bigram_fluency: 2.5,
            mean_lrd_correlation: 0.35,
            mean_non_append_ratio: 0.18,
            session_count: 10,
        };
        let temporal = CognitiveTemporalMetrics {
            sentence_initiation_ratio: 11.0, // Within 1 std dev
            sentence_initiation_variance: 20.0,
            bigram_fluency_ratio: 2.3,
            iki_modality_score: 0.8,
            cognitive_probability: 0.75,
            sentence_count: 5,
            bigram_pairs_analyzed: 100,
        };

        let deviation = compute_baseline_deviation(&baseline, Some(&temporal), None);
        assert!(deviation < 0.3, "deviation={deviation}");
    }

    #[test]
    fn test_baseline_deviation_anomalous() {
        use cpoe_jitter::cognitive::CognitiveTemporalMetrics;

        let baseline = PersonalBaseline {
            mean_sid_ratio: 10.0,
            std_sid_ratio: 2.0,
            mean_bigram_fluency: 2.5,
            mean_lrd_correlation: 0.35,
            mean_non_append_ratio: 0.18,
            session_count: 10,
        };
        // Sudden shift: SID dropped to 3.0 (3.5 std devs from baseline).
        let temporal = CognitiveTemporalMetrics {
            sentence_initiation_ratio: 3.0,
            sentence_initiation_variance: 2.0,
            bigram_fluency_ratio: 1.2,
            iki_modality_score: 0.2,
            cognitive_probability: 0.2,
            sentence_count: 5,
            bigram_pairs_analyzed: 100,
        };

        let deviation = compute_baseline_deviation(&baseline, Some(&temporal), None);
        assert!(deviation > 0.6, "deviation={deviation}");
    }
}
