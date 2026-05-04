// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Writing style fingerprint (word length, punctuation, MinHash n-grams,
//! correction patterns). No raw text is ever stored.
//!
//! Disabled by default; requires explicit consent.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use unicode_normalization::UnicodeNormalization;

const MAX_WORD_LENGTH: usize = 20;
const MINHASH_FUNCTIONS: usize = 100;
const NGRAM_SIZE: usize = 5;
const MIN_NGRAMS: usize = 50;

/// Statistical writing-style fingerprint (content-free).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StyleFingerprint {
    pub consent_given: bool,
    pub word_length_distribution: [f32; MAX_WORD_LENGTH],
    pub punctuation_signature: PunctuationSignature,
    pub ngram_signature: NgramSignature,
    pub correction_rate: f64,
    pub backspace_signature: BackspaceSignature,
    #[serde(default)]
    pub word_pattern: WordPatternSignature,
    #[serde(default)]
    pub sentence_rhythm: SentenceRhythm,
    pub total_chars: u64,
    pub total_words: u64,
    /// Shannon entropy of the word-length distribution
    #[serde(default)]
    pub word_length_entropy: f64,
    /// Entropy of (prev_length, cur_length) transitions
    #[serde(default)]
    pub word_length_transition_entropy: f64,
}

impl Default for StyleFingerprint {
    fn default() -> Self {
        Self {
            consent_given: false,
            word_length_distribution: [0.0; MAX_WORD_LENGTH],
            punctuation_signature: PunctuationSignature::default(),
            ngram_signature: NgramSignature::default(),
            correction_rate: 0.0,
            backspace_signature: BackspaceSignature::default(),
            word_pattern: WordPatternSignature::default(),
            sentence_rhythm: SentenceRhythm::default(),
            total_chars: 0,
            total_words: 0,
            word_length_entropy: 0.0,
            word_length_transition_entropy: 0.0,
        }
    }
}

impl StyleFingerprint {
    pub fn new(consent_given: bool) -> Self {
        Self {
            consent_given,
            ..Default::default()
        }
    }

    /// Weighted merge by `total_chars`.
    pub fn merge(&mut self, other: &StyleFingerprint) {
        let total = self.total_chars + other.total_chars;
        if total == 0 {
            return;
        }

        let self_weight = self.total_chars as f64 / total as f64;
        let other_weight = other.total_chars as f64 / total as f64;

        for i in 0..MAX_WORD_LENGTH {
            self.word_length_distribution[i] = (self.word_length_distribution[i] as f64
                * self_weight
                + other.word_length_distribution[i] as f64 * other_weight)
                as f32;
        }

        self.punctuation_signature
            .merge(&other.punctuation_signature, self_weight, other_weight);
        self.ngram_signature.merge(&other.ngram_signature);
        self.backspace_signature
            .merge(&other.backspace_signature, self_weight, other_weight);
        self.word_pattern.merge(&other.word_pattern);
        self.sentence_rhythm
            .merge(&other.sentence_rhythm, self_weight, other_weight);

        self.correction_rate =
            self.correction_rate * self_weight + other.correction_rate * other_weight;
        self.word_length_entropy = self.word_length_entropy * self_weight
            + other.word_length_entropy * other_weight;
        self.word_length_transition_entropy = self.word_length_transition_entropy * self_weight
            + other.word_length_transition_entropy * other_weight;
        self.total_chars = total;
        self.total_words += other.total_words;
    }

    pub fn avg_word_length(&self) -> f64 {
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;
        for (i, &freq) in self.word_length_distribution.iter().enumerate() {
            let word_len = (i + 1) as f64;
            weighted_sum += word_len * freq as f64;
            total_weight += freq as f64;
        }
        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }

    /// Weighted similarity (0.0-1.0) across all style dimensions.
    pub fn similarity(&self, other: &StyleFingerprint) -> f64 {
        let word_len_hist_sim = histogram_similarity(
            &self.word_length_distribution,
            &other.word_length_distribution,
        );
        let entropy_sim = relative_sim(self.word_length_entropy, other.word_length_entropy);
        let trans_entropy_sim = relative_sim(
            self.word_length_transition_entropy,
            other.word_length_transition_entropy,
        );
        let word_len_sim =
            word_len_hist_sim * 0.60 + entropy_sim * 0.20 + trans_entropy_sim * 0.20;

        let punct_sim = self
            .punctuation_signature
            .similarity(&other.punctuation_signature);
        let ngram_sim = self.ngram_signature.similarity(&other.ngram_signature);
        let correction_sim = 1.0
            - (self.correction_rate - other.correction_rate)
                .abs()
                .min(1.0);
        let backspace_sim = self
            .backspace_signature
            .similarity(&other.backspace_signature);
        let correction_blend = correction_sim * 0.5 + backspace_sim * 0.5;
        let word_pattern_sim = self.word_pattern.similarity(&other.word_pattern);
        let sentence_sim = self.sentence_rhythm.similarity(&other.sentence_rhythm);

        crate::utils::Probability::clamp(
            word_len_sim * 0.15
                + punct_sim * 0.15
                + ngram_sim * 0.20
                + correction_blend * 0.15
                + word_pattern_sim * 0.15
                + sentence_sim * 0.20,
        )
        .get()
    }
}

/// Normalized punctuation character frequencies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PunctuationSignature {
    pub frequencies: HashMap<char, f32>,
    /// Hashed context patterns (privacy-preserving).
    ///
    /// Structural placeholder: populating this requires surrounding-word context
    /// which is intentionally not captured in privacy-preserving mode. The field
    /// is retained for future opt-in content-aware analysis behind explicit consent.
    #[allow(dead_code)] // Requires content access not available in privacy-preserving mode
    pub context_patterns: Vec<u64>,
}

impl PunctuationSignature {
    pub fn record(&mut self, c: char) {
        if c.is_ascii_punctuation() {
            *self.frequencies.entry(c).or_insert(0.0) += 1.0;
        }
    }

    pub fn normalize(&mut self) {
        let total: f32 = self.frequencies.values().sum();
        if total > 0.0 {
            for v in self.frequencies.values_mut() {
                *v /= total;
            }
        }
    }

    /// Weighted merge.
    pub fn merge(&mut self, other: &PunctuationSignature, self_weight: f64, other_weight: f64) {
        for v in self.frequencies.values_mut() {
            *v = (*v as f64 * self_weight) as f32;
        }
        for (k, v) in &other.frequencies {
            let entry = self.frequencies.entry(*k).or_insert(0.0);
            *entry += (*v as f64 * other_weight) as f32;
        }
    }

    pub fn similarity(&self, other: &PunctuationSignature) -> f64 {
        if self.frequencies.is_empty() && other.frequencies.is_empty() {
            return 1.0;
        }

        let all_keys: HashSet<_> = self
            .frequencies
            .keys()
            .chain(other.frequencies.keys())
            .collect();

        let mut sim_sum = 0.0;
        for k in &all_keys {
            let a = *self.frequencies.get(*k).unwrap_or(&0.0) as f64;
            let b = *other.frequencies.get(*k).unwrap_or(&0.0) as f64;
            sim_sum += (1.0 - (a - b).abs()).max(0.0);
        }

        sim_sum / all_keys.len() as f64
    }
}

/// Privacy-preserving n-gram signature via MinHash.
/// Allows Jaccard similarity estimation without revealing content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgramSignature {
    pub minhash: Vec<u64>,
    pub ngram_count: u64,
}

impl Default for NgramSignature {
    fn default() -> Self {
        Self {
            minhash: vec![u64::MAX; MINHASH_FUNCTIONS],
            ngram_count: 0,
        }
    }
}

impl NgramSignature {
    /// Update MinHash slots with a new n-gram.
    pub fn add_ngram(&mut self, ngram: &str) {
        for i in 0..MINHASH_FUNCTIONS {
            let hash = hash_with_seed(ngram, i as u64);
            if hash < self.minhash[i] {
                self.minhash[i] = hash;
            }
        }
        self.ngram_count += 1;
    }

    /// MinHash merge: element-wise minimum.
    pub fn merge(&mut self, other: &NgramSignature) {
        for i in 0..MINHASH_FUNCTIONS {
            self.minhash[i] = self.minhash[i].min(other.minhash[i]);
        }
        self.ngram_count += other.ngram_count;
    }

    /// Estimated Jaccard similarity. Returns 0.5 if either side has < `MIN_NGRAMS`.
    pub fn similarity(&self, other: &NgramSignature) -> f64 {
        if self.ngram_count < MIN_NGRAMS as u64 || other.ngram_count < MIN_NGRAMS as u64 {
            return 0.5;
        }

        let matches = self
            .minhash
            .iter()
            .zip(other.minhash.iter())
            .filter(|(a, b)| a == b)
            .count();

        matches as f64 / MINHASH_FUNCTIONS as f64
    }
}

/// SHA-256 with seed, truncated to `u64` for MinHash.
fn hash_with_seed(s: &str, seed: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.update(seed.to_le_bytes());
    let result = hasher.finalize();
    // SHA-256 always produces 32 bytes; taking the first 8 is infallible.
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&result[..8]);
    u64::from_le_bytes(buf)
}

/// Correction/backspace behavioral signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackspaceSignature {
    /// Average characters typed between consecutive backspaces.
    pub mean_chars_before_backspace: f64,
    /// Average length of consecutive-backspace runs.
    pub mean_consecutive_backspaces: f64,
    /// Backspaces per 100 characters typed.
    pub backspace_frequency: f64,
    /// Fraction of backspaces occurring within 2 characters of prior backspace.
    pub quick_correction_rate: f64,
    /// Fraction of corrections within first 3 chars of a word.
    #[serde(default)]
    pub early_correction_rate: f64,
    /// Fraction of corrections after 5+ chars in a word.
    #[serde(default)]
    pub late_correction_rate: f64,
    /// Average consecutive backspace run length.
    #[serde(default)]
    pub correction_burst_mean: f64,
    /// Fraction of deletions that are word-level (Option+Backspace / Ctrl+Backspace).
    #[serde(default)]
    pub word_delete_rate: f64,
    /// Fraction of deletions that are line-level (Cmd+Backspace).
    #[serde(default)]
    pub line_delete_rate: f64,
    /// Fraction of deletions that are forward-delete (fn+Backspace / Delete key).
    #[serde(default)]
    pub forward_delete_rate: f64,
}

impl Default for BackspaceSignature {
    fn default() -> Self {
        Self {
            mean_chars_before_backspace: 0.0,
            mean_consecutive_backspaces: 0.0,
            backspace_frequency: 0.0,
            quick_correction_rate: 0.0,
            early_correction_rate: 0.0,
            late_correction_rate: 0.0,
            correction_burst_mean: 0.0,
            word_delete_rate: 0.0,
            line_delete_rate: 0.0,
            forward_delete_rate: 0.0,
        }
    }
}

impl BackspaceSignature {
    /// Weighted merge.
    pub fn merge(&mut self, other: &BackspaceSignature, self_weight: f64, other_weight: f64) {
        self.mean_chars_before_backspace = self.mean_chars_before_backspace * self_weight
            + other.mean_chars_before_backspace * other_weight;
        self.mean_consecutive_backspaces = self.mean_consecutive_backspaces * self_weight
            + other.mean_consecutive_backspaces * other_weight;
        self.backspace_frequency =
            self.backspace_frequency * self_weight + other.backspace_frequency * other_weight;
        self.quick_correction_rate =
            self.quick_correction_rate * self_weight + other.quick_correction_rate * other_weight;
        self.early_correction_rate =
            self.early_correction_rate * self_weight + other.early_correction_rate * other_weight;
        self.late_correction_rate =
            self.late_correction_rate * self_weight + other.late_correction_rate * other_weight;
        self.correction_burst_mean =
            self.correction_burst_mean * self_weight + other.correction_burst_mean * other_weight;
        self.word_delete_rate =
            self.word_delete_rate * self_weight + other.word_delete_rate * other_weight;
        self.line_delete_rate =
            self.line_delete_rate * self_weight + other.line_delete_rate * other_weight;
        self.forward_delete_rate =
            self.forward_delete_rate * self_weight + other.forward_delete_rate * other_weight;
    }

    pub fn similarity(&self, other: &BackspaceSignature) -> f64 {
        let sims = [
            relative_sim(
                self.mean_chars_before_backspace,
                other.mean_chars_before_backspace,
            ),
            relative_sim(
                self.mean_consecutive_backspaces,
                other.mean_consecutive_backspaces,
            ),
            relative_sim(self.backspace_frequency, other.backspace_frequency),
            relative_sim(self.quick_correction_rate, other.quick_correction_rate),
            relative_sim(self.early_correction_rate, other.early_correction_rate),
            relative_sim(self.late_correction_rate, other.late_correction_rate),
            relative_sim(self.correction_burst_mean, other.correction_burst_mean),
            relative_sim(self.word_delete_rate, other.word_delete_rate),
            relative_sim(self.line_delete_rate, other.line_delete_rate),
            relative_sim(self.forward_delete_rate, other.forward_delete_rate),
        ];
        sims.iter().sum::<f64>() / sims.len() as f64
    }
}

/// Word-length bigram patterns via MinHash (privacy-preserving).
/// Captures "short-long" vs "uniform" writing style without raw text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordPatternSignature {
    /// MinHash of (prev_word_len, cur_word_len) bigram strings like "3-7"
    pub length_bigram_minhash: Vec<u64>,
    /// Punctuation char to exponential moving average of following word length
    pub punct_word_patterns: HashMap<char, f32>,
    pub total_bigrams: u64,
}

const WORD_PATTERN_MINHASH_SLOTS: usize = 50;

impl Default for WordPatternSignature {
    fn default() -> Self {
        Self {
            length_bigram_minhash: vec![u64::MAX; WORD_PATTERN_MINHASH_SLOTS],
            punct_word_patterns: HashMap::new(),
            total_bigrams: 0,
        }
    }
}

impl WordPatternSignature {
    fn add_bigram(&mut self, prev_len: usize, cur_len: usize) {
        let bigram = format!("{}-{}", prev_len, cur_len);
        for i in 0..WORD_PATTERN_MINHASH_SLOTS {
            let hash = hash_with_seed(&bigram, i as u64 + 1000);
            if hash < self.length_bigram_minhash[i] {
                self.length_bigram_minhash[i] = hash;
            }
        }
        self.total_bigrams += 1;
    }

    fn record_punct_word(&mut self, punct: char, word_len: usize) {
        let alpha = 0.1_f32;
        let entry = self
            .punct_word_patterns
            .entry(punct)
            .or_insert(word_len as f32);
        *entry = *entry * (1.0 - alpha) + word_len as f32 * alpha;
    }

    pub fn merge(&mut self, other: &Self) {
        for i in 0..WORD_PATTERN_MINHASH_SLOTS {
            if i < self.length_bigram_minhash.len()
                && i < other.length_bigram_minhash.len()
            {
                self.length_bigram_minhash[i] =
                    self.length_bigram_minhash[i].min(other.length_bigram_minhash[i]);
            }
        }
        for (&k, &v) in &other.punct_word_patterns {
            let entry = self.punct_word_patterns.entry(k).or_insert(v);
            *entry = (*entry + v) / 2.0;
        }
        self.total_bigrams += other.total_bigrams;
    }

    pub fn similarity(&self, other: &Self) -> f64 {
        let min_bigrams = 20_u64;
        let jaccard = if self.total_bigrams < min_bigrams
            || other.total_bigrams < min_bigrams
        {
            0.5
        } else {
            let matches = self
                .length_bigram_minhash
                .iter()
                .zip(other.length_bigram_minhash.iter())
                .filter(|(a, b)| a == b)
                .count();
            matches as f64 / WORD_PATTERN_MINHASH_SLOTS as f64
        };

        let all_keys: HashSet<_> = self
            .punct_word_patterns
            .keys()
            .chain(other.punct_word_patterns.keys())
            .collect();
        let punct_sim = if all_keys.is_empty() {
            0.5
        } else {
            let mut dot = 0.0_f64;
            let mut mag_a = 0.0_f64;
            let mut mag_b = 0.0_f64;
            for k in &all_keys {
                let a = *self.punct_word_patterns.get(*k).unwrap_or(&0.0) as f64;
                let b =
                    *other.punct_word_patterns.get(*k).unwrap_or(&0.0) as f64;
                dot += a * b;
                mag_a += a * a;
                mag_b += b * b;
            }
            let denom = mag_a.sqrt() * mag_b.sqrt();
            if denom > 0.0 {
                (dot / denom).clamp(0.0, 1.0)
            } else {
                0.5
            }
        };

        jaccard * 0.7 + punct_sim * 0.3
    }
}

/// Sentence-level rhythm: lengths, question/exclamation ratios.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentenceRhythm {
    pub mean_sentence_length: f64,
    pub sentence_length_std: f64,
    pub question_ratio: f64,
    pub exclamation_ratio: f64,
    pub total_sentences: u64,
}

impl Default for SentenceRhythm {
    fn default() -> Self {
        Self {
            mean_sentence_length: 0.0,
            sentence_length_std: 0.0,
            question_ratio: 0.0,
            exclamation_ratio: 0.0,
            total_sentences: 0,
        }
    }
}

impl SentenceRhythm {
    pub fn merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        self.mean_sentence_length = self.mean_sentence_length * self_weight
            + other.mean_sentence_length * other_weight;
        self.sentence_length_std = self.sentence_length_std * self_weight
            + other.sentence_length_std * other_weight;
        self.question_ratio =
            self.question_ratio * self_weight + other.question_ratio * other_weight;
        self.exclamation_ratio = self.exclamation_ratio * self_weight
            + other.exclamation_ratio * other_weight;
        self.total_sentences += other.total_sentences;
    }

    pub fn similarity(&self, other: &Self) -> f64 {
        if self.total_sentences < 3 || other.total_sentences < 3 {
            return 0.5;
        }
        let len_sim =
            relative_sim(self.mean_sentence_length, other.mean_sentence_length);
        let std_sim =
            relative_sim(self.sentence_length_std, other.sentence_length_std);
        let q_sim =
            1.0 - (self.question_ratio - other.question_ratio).abs().min(1.0);
        let e_sim = 1.0
            - (self.exclamation_ratio - other.exclamation_ratio)
                .abs()
                .min(1.0);
        (len_sim * 0.4 + std_sim * 0.2 + q_sim * 0.2 + e_sim * 0.2)
            .clamp(0.0, 1.0)
    }
}

use crate::analysis::stats::relative_similarity as relative_sim;

#[derive(Debug)]
/// Streaming collector that builds a `StyleFingerprint` from keystroke events.
pub struct StyleCollector {
    current_word: String,
    ngram_buffer: VecDeque<char>,
    chars_since_backspace: usize,
    consecutive_backspaces: usize,
    total_backspaces: usize,
    quick_corrections: usize,
    total_chars: usize,
    word_lengths: [usize; MAX_WORD_LENGTH],
    fingerprint: StyleFingerprint,
    /// Running sum of chars-before-backspace gaps (for computing mean).
    chars_before_backspace_sum: usize,
    /// Number of backspace events that ended a non-zero character gap.
    chars_before_backspace_count: usize,
    /// Running sum of consecutive-backspace run lengths.
    consecutive_run_sum: usize,
    /// Number of completed consecutive-backspace runs.
    consecutive_run_count: usize,
    /// Whether the previous keystroke was a backspace (for run tracking).
    prev_was_backspace: bool,
    previous_word_length: Option<usize>,
    chars_in_current_word: usize,
    preceding_punctuation: Option<char>,
    words_since_sentence_end: usize,
    sentence_lengths: Vec<f64>,
    question_count: usize,
    exclamation_count: usize,
    sentence_count: usize,
    early_corrections: usize,
    late_corrections: usize,
    /// Counts of (prev_word_len, cur_word_len) transitions for transition entropy
    word_length_transition_counts: HashMap<(usize, usize), usize>,
    word_deletes: usize,
    line_deletes: usize,
    forward_deletes: usize,
}

impl StyleCollector {
    pub fn new() -> Self {
        Self {
            current_word: String::new(),
            ngram_buffer: VecDeque::with_capacity(NGRAM_SIZE),
            chars_since_backspace: 0,
            consecutive_backspaces: 0,
            total_backspaces: 0,
            quick_corrections: 0,
            total_chars: 0,
            word_lengths: [0; MAX_WORD_LENGTH],
            fingerprint: StyleFingerprint::new(false),
            chars_before_backspace_sum: 0,
            chars_before_backspace_count: 0,
            consecutive_run_sum: 0,
            consecutive_run_count: 0,
            prev_was_backspace: false,
            previous_word_length: None,
            chars_in_current_word: 0,
            preceding_punctuation: None,
            words_since_sentence_end: 0,
            sentence_lengths: Vec::new(),
            question_count: 0,
            exclamation_count: 0,
            sentence_count: 0,
            early_corrections: 0,
            late_corrections: 0,
            word_length_transition_counts: HashMap::new(),
            word_deletes: 0,
            line_deletes: 0,
            forward_deletes: 0,
        }
    }

    /// Process a keystroke with semantic classification.
    /// Falls back to keycode-based backspace detection when semantic is Character.
    pub fn record_keystroke_with_semantic(
        &mut self,
        keycode: u16,
        char_value: Option<char>,
        semantic: crate::sentinel::types::KeystrokeSemantic,
    ) {
        use crate::sentinel::types::KeystrokeSemantic as KS;
        if !self.fingerprint.consent_given {
            return;
        }
        if semantic.is_deletion() {
            match semantic {
                KS::DeleteWord => self.word_deletes += 1,
                KS::DeleteLine => self.line_deletes += 1,
                KS::DeleteForward => self.forward_deletes += 1,
                _ => {}
            }
            self.handle_backspace();
            return;
        }
        self.record_keystroke_inner(keycode, char_value);
    }

    /// Process a keystroke, updating word/ngram/punctuation/backspace stats.
    /// No-op if consent has not been given on the underlying fingerprint.
    pub fn record_keystroke(&mut self, keycode: u16, char_value: Option<char>) {
        if !self.fingerprint.consent_given {
            return;
        }
        if is_backspace_keycode(keycode) {
            self.handle_backspace();
            return;
        }
        self.record_keystroke_inner(keycode, char_value);
    }

    fn record_keystroke_inner(&mut self, _keycode: u16, char_value: Option<char>) {
        // End of a consecutive-backspace run — record it.
        if self.prev_was_backspace && self.consecutive_backspaces > 0 {
            self.consecutive_run_sum += self.consecutive_backspaces;
            self.consecutive_run_count += 1;
        }
        self.consecutive_backspaces = 0;
        self.prev_was_backspace = false;

        if let Some(c) = char_value {
            self.total_chars += 1;
            self.chars_since_backspace += 1;

            if c.is_alphabetic() {
                self.current_word.extend(c.to_lowercase());
                self.chars_in_current_word += 1;
                self.add_to_ngram_buffer(c);
            } else if c.is_whitespace() || c.is_ascii_punctuation() {
                self.finish_word();
                if c.is_ascii_punctuation() {
                    self.fingerprint.punctuation_signature.record(c);
                    if c == '.' || c == '?' || c == '!' {
                        self.finish_sentence(c);
                    }
                    self.preceding_punctuation = Some(c);
                }
            }
        }
    }

    fn handle_backspace(&mut self) {
        self.total_backspaces += 1;
        self.consecutive_backspaces += 1;
        self.prev_was_backspace = true;

        // Record the gap length before this backspace run started.
        if self.consecutive_backspaces == 1 && self.chars_since_backspace > 0 {
            self.chars_before_backspace_sum += self.chars_since_backspace;
            self.chars_before_backspace_count += 1;
        }

        if self.chars_since_backspace <= 2 {
            self.quick_corrections += 1;
        }
        self.chars_since_backspace = 0;

        // Track early/late corrections based on position in current word.
        if self.chars_in_current_word <= 3 {
            self.early_corrections += 1;
        } else if self.chars_in_current_word >= 5 {
            self.late_corrections += 1;
        }
        self.chars_in_current_word = self.chars_in_current_word.saturating_sub(1);

        self.current_word.pop();
        self.ngram_buffer.pop_back();
    }

    fn finish_word(&mut self) {
        if !self.current_word.is_empty() {
            let len = self.current_word.chars().count().min(MAX_WORD_LENGTH);
            if len > 0 {
                self.word_lengths[len - 1] += 1;
                if let Some(prev_len) = self.previous_word_length {
                    self.fingerprint.word_pattern.add_bigram(prev_len, len);
                    *self
                        .word_length_transition_counts
                        .entry((prev_len, len))
                        .or_insert(0) += 1;
                }
                if let Some(punct) = self.preceding_punctuation {
                    self.fingerprint
                        .word_pattern
                        .record_punct_word(punct, len);
                }
                self.previous_word_length = Some(len);
            }
            self.preceding_punctuation = None;
            self.words_since_sentence_end += 1;
            self.fingerprint.total_words += 1;
        }
        self.chars_in_current_word = 0;
        self.current_word.clear();
    }

    fn finish_sentence(&mut self, punct: char) {
        if self.words_since_sentence_end > 0 {
            if self.sentence_lengths.len() < 10000 {
                self.sentence_lengths
                    .push(self.words_since_sentence_end as f64);
            }
            self.sentence_count += 1;
            match punct {
                '?' => self.question_count += 1,
                '!' => self.exclamation_count += 1,
                _ => {}
            }
        }
        self.words_since_sentence_end = 0;
    }

    fn add_to_ngram_buffer(&mut self, c: char) {
        if !self.fingerprint.consent_given {
            return;
        }
        let nc = if c.is_ascii() {
            c.to_ascii_lowercase()
        } else {
            let lowered = c.to_lowercase().next().unwrap_or(c);
            let normalized = lowered.to_string().nfc().collect::<String>();
            normalized.chars().next().unwrap_or(lowered)
        };
        self.ngram_buffer.push_back(nc);
        if self.ngram_buffer.len() > NGRAM_SIZE {
            self.ngram_buffer.pop_front();
        }

        if self.ngram_buffer.len() == NGRAM_SIZE {
            let ngram: String = self.ngram_buffer.iter().collect();
            self.fingerprint.ngram_signature.add_ngram(&ngram);
        }
    }

    /// Snapshot the accumulated stats into a `StyleFingerprint`.
    pub fn current_fingerprint(&self) -> StyleFingerprint {
        let mut fp = self.fingerprint.clone();

        let total_words: usize = self.word_lengths.iter().sum();
        if total_words > 0 {
            for i in 0..MAX_WORD_LENGTH {
                fp.word_length_distribution[i] = self.word_lengths[i] as f32 / total_words as f32;
            }
        }

        // Word-length entropy: Shannon entropy of the distribution
        if total_words > 0 {
            let mut entropy = 0.0f64;
            for &freq in &fp.word_length_distribution {
                let p = freq as f64;
                if p > 0.0 {
                    entropy -= p * p.log2();
                }
            }
            fp.word_length_entropy = if entropy.is_finite() { entropy } else { 0.0 };
        }

        // Word-length transition entropy
        let trans_total: usize = self.word_length_transition_counts.values().sum();
        if trans_total > 0 {
            let mut entropy = 0.0f64;
            for &count in self.word_length_transition_counts.values() {
                let p = count as f64 / trans_total as f64;
                if p > 0.0 {
                    entropy -= p * p.log2();
                }
            }
            fp.word_length_transition_entropy =
                if entropy.is_finite() { entropy } else { 0.0 };
        }

        if self.total_chars > 0 {
            fp.correction_rate = self.total_backspaces as f64 / self.total_chars as f64;
            fp.backspace_signature.backspace_frequency =
                (self.total_backspaces as f64 / self.total_chars as f64) * 100.0;
            if self.total_backspaces > 0 {
                fp.backspace_signature.quick_correction_rate =
                    self.quick_corrections as f64 / self.total_backspaces as f64;
            }
            if self.chars_before_backspace_count > 0 {
                fp.backspace_signature.mean_chars_before_backspace = self.chars_before_backspace_sum
                    as f64
                    / self.chars_before_backspace_count as f64;
            }
            // Include any in-progress backspace run in the mean.
            let run_count = self.consecutive_run_count
                + if self.consecutive_backspaces > 0 {
                    1
                } else {
                    0
                };
            let run_sum = self.consecutive_run_sum + self.consecutive_backspaces;
            if run_count > 0 {
                fp.backspace_signature.mean_consecutive_backspaces =
                    run_sum as f64 / run_count as f64;
            }

            // Early/late correction rates.
            if self.total_backspaces > 0 {
                fp.backspace_signature.early_correction_rate =
                    self.early_corrections as f64 / self.total_backspaces as f64;
                fp.backspace_signature.late_correction_rate =
                    self.late_corrections as f64 / self.total_backspaces as f64;
            }

            // Correction burst mean (same as mean_consecutive_backspaces).
            if run_count > 0 {
                fp.backspace_signature.correction_burst_mean =
                    run_sum as f64 / run_count as f64;
            }

            // Deletion type rates (from semantic classification).
            if self.total_backspaces > 0 {
                let tb = self.total_backspaces as f64;
                fp.backspace_signature.word_delete_rate = self.word_deletes as f64 / tb;
                fp.backspace_signature.line_delete_rate = self.line_deletes as f64 / tb;
                fp.backspace_signature.forward_delete_rate = self.forward_deletes as f64 / tb;
            }
        }

        // Sentence rhythm from accumulated sentence lengths.
        if !self.sentence_lengths.is_empty() {
            let n = self.sentence_lengths.len() as f64;
            let mean = self.sentence_lengths.iter().sum::<f64>() / n;
            let variance = self
                .sentence_lengths
                .iter()
                .map(|&l| (l - mean) * (l - mean))
                .sum::<f64>()
                / n;
            let std = variance.sqrt();
            fp.sentence_rhythm.mean_sentence_length =
                if mean.is_finite() { mean } else { 0.0 };
            fp.sentence_rhythm.sentence_length_std =
                if std.is_finite() { std } else { 0.0 };
            fp.sentence_rhythm.total_sentences = self.sentence_count as u64;
            if self.sentence_count > 0 {
                fp.sentence_rhythm.question_ratio =
                    self.question_count as f64 / self.sentence_count as f64;
                fp.sentence_rhythm.exclamation_ratio =
                    self.exclamation_count as f64 / self.sentence_count as f64;
            }
        }

        fp.total_chars = self.total_chars as u64;
        fp.punctuation_signature.normalize();

        fp
    }

    /// Set whether consent has been given for style fingerprinting.
    pub fn set_consent(&mut self, granted: bool) {
        self.fingerprint.consent_given = granted;
    }

    pub fn sample_count(&self) -> usize {
        self.total_chars
    }

    pub fn reset(&mut self) {
        let consent = self.fingerprint.consent_given;
        self.current_word.clear();
        self.ngram_buffer.clear();
        self.chars_since_backspace = 0;
        self.consecutive_backspaces = 0;
        self.total_backspaces = 0;
        self.quick_corrections = 0;
        self.total_chars = 0;
        self.word_lengths = [0; MAX_WORD_LENGTH];
        self.fingerprint = StyleFingerprint::new(consent);
        self.chars_before_backspace_sum = 0;
        self.chars_before_backspace_count = 0;
        self.consecutive_run_sum = 0;
        self.consecutive_run_count = 0;
        self.prev_was_backspace = false;
        self.previous_word_length = None;
        self.chars_in_current_word = 0;
        self.preceding_punctuation = None;
        self.words_since_sentence_end = 0;
        self.sentence_lengths.clear();
        self.question_count = 0;
        self.exclamation_count = 0;
        self.sentence_count = 0;
        self.early_corrections = 0;
        self.late_corrections = 0;
        self.word_length_transition_counts.clear();
    }
}

impl Default for StyleCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross-platform backspace detection (macOS/Linux/Windows/ASCII DEL).
fn is_backspace_keycode(keycode: u16) -> bool {
    keycode == 0x33 || keycode == 14 || keycode == 0x08 || keycode == 0x7F
}

/// Bhattacharyya coefficient between two f32 histograms.
pub fn histogram_similarity(a: &[f32], b: &[f32]) -> f64 {
    let sum: f64 = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| ((x.max(0.0) as f64) * (y.max(0.0) as f64)).sqrt())
        .sum();
    sum.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_style_fingerprint_default() {
        let fp = StyleFingerprint::default();
        assert!(!fp.consent_given);
        assert_eq!(fp.total_chars, 0);
    }

    #[test]
    fn test_minhash_similarity() {
        let mut sig1 = NgramSignature::default();
        let mut sig2 = NgramSignature::default();

        for word in ["the", "quick", "brown", "fox", "jumps"] {
            for ngram in word.as_bytes().windows(3) {
                let s = std::str::from_utf8(ngram).expect("ascii input");
                sig1.add_ngram(s);
                sig2.add_ngram(s);
            }
        }

        for i in 0..50 {
            sig1.add_ngram(&format!("xxx{}", i));
            sig2.add_ngram(&format!("xxx{}", i));
        }

        let sim = sig1.similarity(&sig2);
        assert!(sim > 0.9, "Same content should have high similarity");
    }

    #[test]
    fn test_style_collector() {
        let mut collector = StyleCollector::new();
        collector.fingerprint.consent_given = true;

        for c in "hello".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some(' '));
        for c in "world".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some('.'));

        let fp = collector.current_fingerprint();
        assert_eq!(fp.total_words, 2);
        assert!(fp.total_chars > 0);
    }

    #[test]
    fn test_punctuation_signature() {
        let mut sig = PunctuationSignature::default();
        sig.record('.');
        sig.record('.');
        sig.record(',');
        sig.normalize();

        assert!(sig.frequencies.get(&'.').unwrap() > sig.frequencies.get(&',').unwrap());
    }

    #[test]
    fn test_word_pattern_signature() {
        let mut sig = WordPatternSignature::default();
        // Add enough bigrams to exceed min_bigrams threshold (20).
        for i in 0..25 {
            sig.add_bigram(i % 5 + 1, i % 7 + 1);
        }
        assert_eq!(sig.total_bigrams, 25);

        sig.record_punct_word('.', 5);
        sig.record_punct_word(',', 3);

        let sim = sig.similarity(&sig);
        assert!(
            sim > 0.85,
            "Self-similarity should be high, got {}",
            sim
        );

        let other = WordPatternSignature::default();
        let sim2 = sig.similarity(&other);
        assert!(
            (sim2 - 0.5).abs() < 0.01,
            "Similarity with empty should be ~0.5, got {}",
            sim2
        );
    }

    #[test]
    fn test_sentence_rhythm() {
        let mut collector = StyleCollector::new();
        collector.fingerprint.consent_given = true;

        // Type "hello world. foo bar? baz!"
        for c in "hello".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some(' '));
        for c in "world".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some('.'));
        collector.record_keystroke(0, Some(' '));
        for c in "foo".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some(' '));
        for c in "bar".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some('?'));
        collector.record_keystroke(0, Some(' '));
        for c in "baz".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some('!'));

        let fp = collector.current_fingerprint();
        assert_eq!(fp.sentence_rhythm.total_sentences, 3);
        assert!(
            fp.sentence_rhythm.mean_sentence_length > 0.0,
            "Mean sentence length should be positive"
        );
        assert!(
            fp.sentence_rhythm.question_ratio > 0.0,
            "Question ratio should be positive"
        );
        assert!(
            fp.sentence_rhythm.exclamation_ratio > 0.0,
            "Exclamation ratio should be positive"
        );
    }

    #[test]
    fn test_backspace_early_late() {
        let mut collector = StyleCollector::new();
        collector.fingerprint.consent_given = true;

        // Type "ab" then backspace (early: chars_in_current_word=2 <= 3)
        collector.record_keystroke(0, Some('a'));
        collector.record_keystroke(0, Some('b'));
        collector.record_keystroke(0x33, None); // backspace (early)

        // Type "cdefgh" then backspace (late: chars_in_current_word=6 >= 5)
        // Current word is now "a" from above, so start fresh with space
        collector.record_keystroke(0, Some(' '));
        for c in "cdefgh".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0x33, None); // backspace (late)

        let fp = collector.current_fingerprint();
        assert!(
            fp.backspace_signature.early_correction_rate > 0.0,
            "Should have early corrections"
        );
        assert!(
            fp.backspace_signature.late_correction_rate > 0.0,
            "Should have late corrections"
        );
    }

    #[test]
    fn test_word_length_entropy() {
        let mut collector = StyleCollector::new();
        collector.fingerprint.consent_given = true;

        // Type words of varying lengths: "a bb ccc dddd eeeee"
        for word in ["a", "bb", "ccc", "dddd", "eeeee"] {
            for c in word.chars() {
                collector.record_keystroke(0, Some(c));
            }
            collector.record_keystroke(0, Some(' '));
        }

        let fp = collector.current_fingerprint();
        assert!(
            fp.word_length_entropy > 0.0,
            "entropy should be positive for varied word lengths, got {}",
            fp.word_length_entropy
        );
    }

    #[test]
    fn test_word_length_transition_entropy() {
        let mut collector = StyleCollector::new();
        collector.fingerprint.consent_given = true;

        // Type multiple words to generate transitions
        for word in ["hello", "world", "foo", "bar", "baz", "qux"] {
            for c in word.chars() {
                collector.record_keystroke(0, Some(c));
            }
            collector.record_keystroke(0, Some(' '));
        }

        let fp = collector.current_fingerprint();
        assert!(
            fp.word_length_transition_entropy > 0.0,
            "transition entropy should be positive, got {}",
            fp.word_length_transition_entropy
        );
    }

    #[test]
    fn test_word_length_entropy_uniform() {
        let mut collector = StyleCollector::new();
        collector.fingerprint.consent_given = true;

        // All same-length words should yield lower entropy than varied
        for _ in 0..10 {
            for c in "abc".chars() {
                collector.record_keystroke(0, Some(c));
            }
            collector.record_keystroke(0, Some(' '));
        }
        let uniform_fp = collector.current_fingerprint();

        collector.reset();
        collector.set_consent(true);
        for word in ["a", "bb", "ccc", "dddd", "eeeee", "ffffff", "ggggggg"] {
            for c in word.chars() {
                collector.record_keystroke(0, Some(c));
            }
            collector.record_keystroke(0, Some(' '));
        }
        let varied_fp = collector.current_fingerprint();

        assert!(
            varied_fp.word_length_entropy > uniform_fp.word_length_entropy,
            "varied words should have higher entropy ({}) than uniform ({})",
            varied_fp.word_length_entropy,
            uniform_fp.word_length_entropy
        );
    }

    #[test]
    fn test_ngram_size_five() {
        let mut collector = StyleCollector::new();
        collector.fingerprint.consent_given = true;

        // Type exactly 5 alphabetic chars to produce one 5-gram.
        for c in "abcde".chars() {
            collector.record_keystroke(0, Some(c));
        }
        let fp = collector.current_fingerprint();
        assert_eq!(
            fp.ngram_signature.ngram_count, 1,
            "Should have exactly one 5-gram"
        );

        // 4 chars should produce zero n-grams.
        collector.reset();
        collector.set_consent(true);
        for c in "abcd".chars() {
            collector.record_keystroke(0, Some(c));
        }
        let fp2 = collector.current_fingerprint();
        assert_eq!(
            fp2.ngram_signature.ngram_count, 0,
            "4 chars should produce zero 5-grams"
        );
    }
}
