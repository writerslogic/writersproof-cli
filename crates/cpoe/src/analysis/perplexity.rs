// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Character-level n-gram perplexity model for authorship anomaly detection.
//!
//! Perplexity measures how "surprised" a language model is by new text.
//! Low perplexity = text matches learned writing patterns (natural).
//! High perplexity = text diverges from learned patterns (anomalous).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ── Constants ────────────────────────────────────────────────────────────────

/// Minimum training corpus size before perplexity scores are meaningful.
const MIN_TRAINING_SAMPLES: usize = 1000;

/// Lidstone smoothing alpha. Smaller than Laplace (1.0) to keep the
/// distribution sharper, making perplexity more sensitive to anomalies.
const SMOOTHING_ALPHA: f64 = 0.1;

/// Alphabet size for smoothing denominator (256 byte values).
const ALPHABET_SIZE: f64 = 256.0;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors from perplexity computation.
#[derive(Debug, Clone)]
pub enum PerplexityError {
    /// Model has not been trained with enough data.
    Undertrained {
        sample_count: usize,
        required: usize,
    },
    /// Input text is too short for the n-gram order.
    InputTooShort {
        input_len: usize,
        ngram_order: usize,
    },
    /// No valid n-grams were evaluated (degenerate input).
    NoValidNgrams,
}

impl fmt::Display for PerplexityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undertrained {
                sample_count,
                required,
            } => write!(
                f,
                "model undertrained: {sample_count} samples < {required} required"
            ),
            Self::InputTooShort {
                input_len,
                ngram_order,
            } => write!(
                f,
                "input too short: {input_len} chars <= n-gram order {ngram_order}"
            ),
            Self::NoValidNgrams => write!(f, "no valid n-grams evaluated"),
        }
    }
}

impl std::error::Error for PerplexityError {}

// ── Model ────────────────────────────────────────────────────────────────────

/// Character-level n-gram model for perplexity-based authorship anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerplexityModel {
    /// N-gram order (context length in characters).
    pub n: usize,
    /// Per-context character frequency counts.
    pub counts: HashMap<String, HashMap<char, usize>>,
    /// Total observations per context string.
    pub totals: HashMap<String, usize>,
    /// Total characters ingested during training.
    pub sample_count: usize,
}

impl PerplexityModel {
    /// Create an empty model with the given n-gram order.
    pub fn new(n: usize) -> Self {
        Self {
            n,
            ..Default::default()
        }
    }

    /// Ingest text, updating n-gram frequency tables.
    pub fn train(&mut self, text: &str) {
        let char_indices: Vec<(usize, char)> = text.char_indices().collect();
        if char_indices.len() <= self.n {
            return;
        }

        for i in 0..(char_indices.len() - self.n) {
            let start_byte = char_indices[i].0;
            let end_byte = char_indices[i + self.n].0;
            let context = &text[start_byte..end_byte];
            let next_char = char_indices[i + self.n].1;

            *self.totals.entry(context.to_owned()).or_default() += 1;
            *self
                .counts
                .entry(context.to_owned())
                .or_default()
                .entry(next_char)
                .or_default() += 1;
        }
        self.sample_count += char_indices.len();
    }

    /// Perplexity of `text` under the trained model.
    /// Low = natural, high = anomalous.
    pub fn compute_perplexity(&self, text: &str) -> Result<f64, PerplexityError> {
        if self.sample_count < MIN_TRAINING_SAMPLES {
            return Err(PerplexityError::Undertrained {
                sample_count: self.sample_count,
                required: MIN_TRAINING_SAMPLES,
            });
        }

        let char_indices: Vec<(usize, char)> = text.char_indices().collect();
        if char_indices.len() <= self.n {
            return Err(PerplexityError::InputTooShort {
                input_len: char_indices.len(),
                ngram_order: self.n,
            });
        }

        let mut log_prob_sum = 0.0;
        let mut count = 0usize;

        for i in 0..(char_indices.len() - self.n) {
            let start_byte = char_indices[i].0;
            let end_byte = char_indices[i + self.n].0;
            let context = &text[start_byte..end_byte];
            let next_char = char_indices[i + self.n].1;

            let prob = if let Some(context_counts) = self.counts.get(context) {
                let char_count = *context_counts.get(&next_char).unwrap_or(&0);
                let total = *self.totals.get(context).unwrap_or(&1);
                (char_count as f64 + SMOOTHING_ALPHA)
                    / (total as f64 + SMOOTHING_ALPHA * ALPHABET_SIZE)
            } else {
                SMOOTHING_ALPHA / (self.sample_count as f64 + ALPHABET_SIZE)
            };

            log_prob_sum += prob.ln();
            count += 1;
        }

        if count == 0 {
            return Err(PerplexityError::NoValidNgrams);
        }

        let ppl = (-log_prob_sum / count as f64).exp();
        Ok(if ppl.is_finite() { ppl } else { 1.0 })
    }

    /// Convenience: compute perplexity, returning 1.0 on any error.
    /// Use this when the caller doesn't need to distinguish error types.
    pub fn perplexity_or_default(&self, text: &str) -> f64 {
        self.compute_perplexity(text).unwrap_or(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_model_defaults() {
        let model = PerplexityModel::new(3);
        assert_eq!(model.n, 3);
        assert_eq!(model.sample_count, 0);
        assert!(model.counts.is_empty());
        assert!(model.totals.is_empty());
    }

    #[test]
    fn test_train_populates_ngrams() {
        let mut model = PerplexityModel::new(2);
        model.train("hello world");

        assert!(model.sample_count > 0);
        assert!(!model.counts.is_empty());
        assert!(model.counts.contains_key("he"));
        assert!(model.counts.contains_key("ll"));
    }

    #[test]
    fn test_train_short_text_noop() {
        let mut model = PerplexityModel::new(5);
        model.train("hi");

        assert!(model.counts.is_empty());
    }

    #[test]
    fn test_perplexity_undertrained_returns_error() {
        let mut model = PerplexityModel::new(2);
        model.train("short");

        assert!(matches!(
            model.compute_perplexity("test text"),
            Err(PerplexityError::Undertrained { .. })
        ));
        assert!((model.perplexity_or_default("test") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_perplexity_familiar_text_lower_than_random() {
        let mut model = PerplexityModel::new(2);
        let training = "the quick brown fox jumps over the lazy dog ".repeat(50);
        model.train(&training);

        let ppl_same = model.perplexity_or_default("the quick brown fox jumps over the lazy dog");
        let ppl_random = model.perplexity_or_default("xzqw jklm npqr stvw yzab cdef ghij");

        assert!(
            ppl_same < ppl_random,
            "Perplexity of familiar text ({ppl_same}) should be lower than random ({ppl_random})"
        );
    }

    #[test]
    fn test_perplexity_short_input_returns_error() {
        let mut model = PerplexityModel::new(3);
        let training = "the quick brown fox jumps over the lazy dog ".repeat(50);
        model.train(&training);

        assert!(matches!(
            model.compute_perplexity("ab"),
            Err(PerplexityError::InputTooShort { .. })
        ));
    }

    #[test]
    fn test_incremental_training() {
        let mut model = PerplexityModel::new(2);
        model.train("hello ");
        let count_after_first = model.sample_count;
        model.train("world ");
        assert!(model.sample_count > count_after_first);
    }

    #[test]
    fn test_entry_api_dedup() {
        let mut model = PerplexityModel::new(2);
        model.train("aaaa");
        // "aa" context should have a single entry for 'a'
        assert_eq!(model.counts.get("aa").map(|m| m.len()), Some(1));
        // Total should be 2 (positions 0 and 1)
        assert_eq!(model.totals.get("aa"), Some(&2));
    }
}
