// SPDX-License-Identifier: Apache-2.0

//! Transcription Attack Detector: detects "Copy-Type" attack where a human
//! transcribes AI-generated text. Based on arXiv:2601.17280 — authentic writing
//! is dynamic (monitoring + revising), transcription is linear (visual → motor).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionData {
    pub total_keystrokes: usize,
    /// Backspace/delete count.
    pub deletions: usize,
    /// Non-sequential insertions (cursor repositioned before typing).
    pub insertions: usize,
    /// Average keystrokes between pauses > 2s.
    pub avg_burst_length: f64,
    /// Distinct cursor jump positions.
    pub cursor_repositions: usize,
    pub final_char_count: usize,
}

pub struct TranscriptionDetector {
    data: TranscriptionData,
}

impl TranscriptionDetector {
    pub fn from_data(data: &TranscriptionData) -> Self {
        Self { data: data.clone() }
    }

    /// Ratio of net progress to total keystrokes.
    /// Composition: 0.60-0.80, Transcription: >0.92, Perfect: ~1.0
    ///
    /// Returns 0.0 for empty documents: no keystrokes means no evidence of
    /// linearity, not perfect linearity. Returning 1.0 would incorrectly
    /// flag empty documents as transcription.
    pub fn compute_linearity_score(&self) -> f64 {
        if self.data.total_keystrokes == 0 {
            return 0.0;
        }

        let revision_effort = self.data.deletions + self.data.insertions;
        ((self.data.total_keystrokes as f64 - revision_effort as f64)
            / self.data.total_keystrokes as f64)
            .max(0.0)
    }

    /// Deletions per 100 keystrokes. Composition: 8-25, Transcription: <3.
    pub fn compute_revision_density(&self) -> f64 {
        if self.data.total_keystrokes == 0 {
            return 0.0;
        }
        (self.data.deletions as f64 / self.data.total_keystrokes as f64) * 100.0
    }

    /// Cursor repositions per 1000 characters.
    pub fn compute_nonlinearity_index(&self) -> f64 {
        if self.data.final_char_count == 0 {
            return 0.0;
        }
        (self.data.cursor_repositions as f64 / self.data.final_char_count as f64) * 1000.0
    }

    /// Requires at least 2 of 3 signals to converge before flagging.
    pub fn is_transcription_attack(&self) -> bool {
        if self.data.total_keystrokes == 0 || self.data.final_char_count == 0 {
            return false;
        }

        let linearity = self.compute_linearity_score();
        let revision_density = self.compute_revision_density();
        let nonlinearity = self.compute_nonlinearity_index();

        let linear_typing = linearity > 0.92 && self.data.avg_burst_length > 15.0;
        let no_revisions = revision_density < 3.0;
        let no_jumping = nonlinearity < 2.0;

        let signals = [linear_typing, no_revisions, no_jumping];
        signals.iter().filter(|&&s| s).count() >= 2
    }

    pub fn analyze(&self) -> TranscriptionAnalysis {
        let linearity = self.compute_linearity_score();
        let revision_density = self.compute_revision_density();
        let nonlinearity = self.compute_nonlinearity_index();
        let is_attack = self.is_transcription_attack();

        let explanation = if is_attack {
            format!(
                "Writing pattern consistent with transcription: \
                 linearity={:.3} (threshold: 0.92), \
                 revision_density={:.1}/100ks (threshold: 3.0), \
                 cursor_repositions={:.1}/1000ch (threshold: 2.0)",
                linearity, revision_density, nonlinearity
            )
        } else {
            format!(
                "Writing pattern consistent with composition: \
                 linearity={:.3}, revision_density={:.1}/100ks, \
                 cursor_repositions={:.1}/1000ch",
                linearity, revision_density, nonlinearity
            )
        };

        TranscriptionAnalysis {
            linearity_score: linearity,
            revision_density,
            nonlinearity_index: nonlinearity,
            avg_burst_length: self.data.avg_burst_length,
            is_transcription: is_attack,
            explanation,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionAnalysis {
    pub linearity_score: f64,
    pub revision_density: f64,
    pub nonlinearity_index: f64,
    pub avg_burst_length: f64,
    pub is_transcription: bool,
    pub explanation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genuine_composition() {
        let data = TranscriptionData {
            total_keystrokes: 5000,
            deletions: 600,
            insertions: 150,
            avg_burst_length: 8.5,
            cursor_repositions: 85,
            final_char_count: 4200,
        };
        let detector = TranscriptionDetector::from_data(&data);
        assert!(!detector.is_transcription_attack());
        assert!(detector.compute_linearity_score() < 0.92);
    }

    #[test]
    fn test_transcription_detected() {
        let data = TranscriptionData {
            total_keystrokes: 5000,
            deletions: 50,
            insertions: 10,
            avg_burst_length: 22.0,
            cursor_repositions: 3,
            final_char_count: 4900,
        };
        let detector = TranscriptionDetector::from_data(&data);
        assert!(detector.is_transcription_attack());
        assert!(detector.compute_linearity_score() > 0.92);
    }

    #[test]
    fn test_empty_input_not_flagged() {
        let data = TranscriptionData {
            total_keystrokes: 0,
            deletions: 0,
            insertions: 0,
            avg_burst_length: 20.0,
            cursor_repositions: 0,
            final_char_count: 0,
        };
        let detector = TranscriptionDetector::from_data(&data);
        assert!(!detector.is_transcription_attack());
    }

    #[test]
    fn test_edge_case_fast_typist() {
        let data = TranscriptionData {
            total_keystrokes: 5000,
            deletions: 400,
            insertions: 100,
            avg_burst_length: 18.0,
            cursor_repositions: 45,
            final_char_count: 4500,
        };
        let detector = TranscriptionDetector::from_data(&data);
        assert!(!detector.is_transcription_attack());
    }
}
