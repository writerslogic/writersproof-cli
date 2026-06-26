// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Accumulates cognitive writing signals from the keystroke stream in real-time.
//!
//! As keystrokes arrive in the sentinel, this accumulator tracks:
//! - Word boundaries with timing (for LRD correlation)
//! - Edit operations (append vs insert vs delete, for non-append ratio)
//! - Sentence boundaries (for sentence initiation delay)
//! - Correction patterns (for error fingerprinting)
//!
//! At checkpoint time, the accumulated data feeds into the protocol-level
//! cognitive analyzer to produce `CognitiveLayerMetrics`.

use std::collections::VecDeque;

use zeroize::Zeroize;

use authorproof_protocol::forensics::cognitive::{
    analyze_cognitive_content, analyze_error_fingerprint, CorrectionEvent, CorrectionType, EditOp,
    WordBoundaryEvent,
};
use cpoe_jitter::cognitive::{analyze_cognitive_temporal, TimedKeystroke};

/// Maximum word boundaries tracked per session (prevents unbounded growth).
const MAX_WORD_BOUNDARIES: usize = 5000;
/// Maximum edit operations tracked per session.
const MAX_EDIT_OPS: usize = 10000;
/// Maximum timed keystrokes for temporal analysis.
const MAX_TIMED_KEYSTROKES: usize = 20000;
/// Maximum correction events tracked.
const MAX_CORRECTIONS: usize = 2000;

/// Real-time accumulator for cognitive writing signals.
///
/// Uses `VecDeque` circular buffers so that when capacity is reached,
/// the oldest entries are evicted. This ensures metrics always reflect
/// the most recent behavior rather than silently ignoring late-session data.
#[derive(Debug, Clone)]
pub struct CognitiveAccumulator {
    /// Word boundary events (pause before each word).
    word_boundaries: VecDeque<WordBoundaryEvent>,
    /// Sequence of edit operations.
    edit_ops: VecDeque<EditOp>,
    /// Timed keystrokes for temporal analysis (SID, bigram fluency, modality).
    timed_keystrokes: VecDeque<TimedKeystroke>,
    /// Correction events for error fingerprinting.
    corrections: VecDeque<CorrectionEvent>,

    // Internal state for word boundary detection.
    current_word: String,
    word_start_pause_ms: u32,
    last_was_separator: bool,
    last_was_sentence_end: bool,
    last_keystroke_ns: i64,

    // State for edit operation tracking.
    file_size_at_last_event: i64,
    consecutive_deletes: usize,
}

impl Default for CognitiveAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl CognitiveAccumulator {
    pub fn new() -> Self {
        Self {
            word_boundaries: VecDeque::with_capacity(256),
            edit_ops: VecDeque::with_capacity(512),
            timed_keystrokes: VecDeque::with_capacity(1024),
            corrections: VecDeque::with_capacity(64),
            current_word: String::with_capacity(32),
            word_start_pause_ms: 0,
            last_was_separator: true,
            last_was_sentence_end: false,
            last_keystroke_ns: 0,
            file_size_at_last_event: 0,
            consecutive_deletes: 0,
        }
    }

    /// Record a keystroke event. Called from sentinel core on each accepted keyDown.
    pub fn record_keystroke(
        &mut self,
        char_value: Option<char>,
        timestamp_ns: i64,
        iki_ns: u64,
        size_delta: i32,
        file_size: i64,
    ) {
        let iki_us = iki_ns / 1000;
        let char_byte = char_value.map(|c| c as u8).unwrap_or(0);

        // Track timed keystroke for temporal analysis (SID + bigram + modality).
        if self.timed_keystrokes.len() >= MAX_TIMED_KEYSTROKES {
            self.timed_keystrokes.pop_front();
        }
        self.timed_keystrokes.push_back(TimedKeystroke {
            iki_us,
            char_byte,
            after_sentence_end: self.last_was_sentence_end,
        });

        // Track edit operation type.
        if self.edit_ops.len() >= MAX_EDIT_OPS {
            self.edit_ops.pop_front();
        }
        let op = classify_edit_op(size_delta, file_size, self.file_size_at_last_event);
        self.edit_ops.push_back(op);

        // Track correction patterns.
        if op == EditOp::Delete {
            self.consecutive_deletes += 1;
        } else {
            if self.consecutive_deletes > 0 {
                if self.corrections.len() >= MAX_CORRECTIONS {
                    self.corrections.pop_front();
                }
                let correction_type = classify_correction(self.consecutive_deletes);
                self.corrections.push_back(CorrectionEvent {
                    correction_type,
                    char_count: self.consecutive_deletes,
                });
            }
            self.consecutive_deletes = 0;
        }
        self.file_size_at_last_event = file_size;

        // Word boundary detection from character stream.
        if let Some(ch) = char_value {
            let is_separator = ch.is_whitespace()
                || ch == '.'
                || ch == ','
                || ch == '!'
                || ch == '?'
                || ch == ';'
                || ch == ':';
            let is_sentence_end = ch == '.' || ch == '!' || ch == '?';

            if is_separator && !self.current_word.is_empty() {
                // Word just completed — record boundary with pre-word pause.
                if self.word_boundaries.len() >= MAX_WORD_BOUNDARIES {
                    self.word_boundaries.pop_front();
                }
                let tier = authorproof_protocol::forensics::cognitive::word_frequency_tier(
                    &self.current_word,
                );
                self.word_boundaries.push_back(WordBoundaryEvent {
                    pre_word_pause_ms: self.word_start_pause_ms,
                    frequency_tier: tier,
                });
                self.current_word.zeroize();
                self.last_was_separator = true;
            } else if !is_separator {
                if self.last_was_separator {
                    // Starting a new word — record the pause before it.
                    self.word_start_pause_ms = (iki_us / 1000) as u32;
                }
                self.current_word.push(ch);
                self.last_was_separator = false;
            }

            if is_sentence_end {
                self.last_was_sentence_end = true;
            } else if !is_separator {
                self.last_was_sentence_end = false;
            }
        }

        self.last_keystroke_ns = timestamp_ns;
    }

    /// Produce cognitive analysis results from accumulated data.
    /// Called at checkpoint time to enrich `WritingModeAnalysis`.
    pub fn analyze(&self) -> Option<super::writing_mode::CognitiveLayerMetrics> {
        // VecDeque may not be contiguous; collect to Vec for slice APIs.
        let timed_ks: Vec<_> = self.timed_keystrokes.iter().cloned().collect();
        let word_bs: Vec<_> = self.word_boundaries.iter().cloned().collect();
        let edit_os: Vec<_> = self.edit_ops.iter().copied().collect();
        let corrs: Vec<_> = self.corrections.iter().cloned().collect();

        let temporal = analyze_cognitive_temporal(&timed_ks);
        let content = analyze_cognitive_content(&word_bs, &edit_os);
        let error_fp = analyze_error_fingerprint(&corrs);

        // Need at least temporal or content analysis to produce meaningful metrics.
        let t = temporal.as_ref();
        let has_content = content.word_boundary_count >= 20 || content.total_edit_ops >= 50;

        if t.is_none() && !has_content {
            return None;
        }

        // Compute spoofing indicator: max disagreement between available signals.
        let mut scores: Vec<f64> = Vec::new();
        if let Some(t) = t {
            scores.push(t.cognitive_probability);
        }
        if has_content {
            scores.push(content.cognitive_probability);
        }
        let spoofing = compute_max_disagreement(&scores);

        Some(super::writing_mode::CognitiveLayerMetrics {
            sentence_initiation_ratio: t.map(|t| t.sentence_initiation_ratio).unwrap_or(0.0),
            iki_modality_score: t.map(|t| t.iki_modality_score).unwrap_or(0.0),
            bigram_fluency_ratio: t.map(|t| t.bigram_fluency_ratio).unwrap_or(0.0),
            lrd_correlation: content.lrd_correlation,
            non_append_ratio: content.non_append_ratio,
            semantic_correction_ratio: error_fp.as_ref().map(|fp| fp.semantic_ratio).unwrap_or(0.0),
            spoofing_indicator: spoofing,
            baseline_deviation: 0.0, // Requires cross-session data; populated by caller
        })
    }

    /// Number of word boundaries accumulated so far.
    pub fn word_boundary_count(&self) -> usize {
        self.word_boundaries.len()
    }

    /// Number of timed keystrokes accumulated.
    pub fn keystroke_count(&self) -> usize {
        self.timed_keystrokes.len()
    }
}

fn classify_edit_op(size_delta: i32, file_size: i64, prev_file_size: i64) -> EditOp {
    if size_delta < 0 {
        EditOp::Delete
    } else if size_delta == 0 {
        EditOp::CursorJump
    } else {
        // Heuristic: if new file_size == prev + delta (simple append at end),
        // classify as Append. If there's a position shift, it's an Insert.
        // Without cursor position, we use the conservative heuristic that
        // monotonically increasing file sizes with positive deltas are appends.
        if file_size == prev_file_size + size_delta as i64 {
            EditOp::Append
        } else {
            EditOp::Insert
        }
    }
}

fn classify_correction(delete_count: usize) -> CorrectionType {
    match delete_count {
        1 => CorrectionType::SingleCharTypo,
        2..=3 => CorrectionType::SingleCharTypo, // Short typo corrections
        4..=6 => CorrectionType::WordDeletion,
        _ => CorrectionType::SemanticRevision,
    }
}

fn compute_max_disagreement(scores: &[f64]) -> f64 {
    if scores.len() < 2 {
        return 0.0;
    }
    let mut lo = f64::MAX;
    let mut hi = f64::MIN;
    for &s in scores {
        if s < lo {
            lo = s;
        }
        if s > hi {
            hi = s;
        }
    }
    let max_d = hi - lo;
    if max_d < 0.4 {
        0.0
    } else {
        cpoe_jitter::sigmoid(max_d, 8.0, 0.6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator_word_boundaries() {
        let mut acc = CognitiveAccumulator::new();
        // Type "the quick" with varying pauses.
        for (i, ch) in "the quick".chars().enumerate() {
            let iki_ns = if i == 4 { 500_000_000 } else { 120_000_000 }; // 500ms before "quick"
            acc.record_keystroke(
                Some(ch),
                (i as i64 + 1) * 1_000_000_000,
                iki_ns,
                1,
                i as i64 + 1,
            );
        }
        // "the" gets recorded as a word when space arrives.
        assert_eq!(acc.word_boundary_count(), 1);
    }

    #[test]
    fn test_accumulator_edit_ops() {
        let mut acc = CognitiveAccumulator::new();
        // Simulate appends then a deletion.
        for i in 0..10 {
            acc.record_keystroke(Some('a'), i * 100_000_000, 100_000_000, 1, i + 1);
        }
        // Delete 3 chars.
        for i in 10..13 {
            acc.record_keystroke(None, i * 100_000_000, 100_000_000, -1, 10 - (i - 10));
        }
        // Next char triggers correction recording.
        acc.record_keystroke(Some('b'), 13 * 100_000_000, 100_000_000, 1, 8);
        assert_eq!(acc.corrections.len(), 1);
        assert_eq!(acc.corrections[0].char_count, 3);
    }

    #[test]
    fn test_accumulator_sentence_boundary() {
        let mut acc = CognitiveAccumulator::new();
        // Type "Hi. Ok"
        let text = "Hi. Ok";
        for (i, ch) in text.chars().enumerate() {
            let iki_ns = if ch == 'O' {
                1_500_000_000
            } else {
                100_000_000
            };
            acc.record_keystroke(
                Some(ch),
                (i as i64 + 1) * 1_000_000_000,
                iki_ns,
                1,
                i as i64 + 1,
            );
        }
        // Check that the 'O' after '. ' was marked as after_sentence_end.
        let o_idx = acc
            .timed_keystrokes
            .iter()
            .position(|k| k.char_byte == b'O')
            .unwrap();
        assert!(acc.timed_keystrokes[o_idx].after_sentence_end);
    }

    #[test]
    fn test_analyze_insufficient_data() {
        let acc = CognitiveAccumulator::new();
        assert!(acc.analyze().is_none());
    }
}
