// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Cross-window text comparison for transcription detection.
//!
//! Compares a rolling buffer of recently typed characters against text visible
//! in other windows on the same machine. High similarity indicates the user is
//! transcribing content from another window rather than composing original text.
//!
//! Privacy: only the source app name, window title, similarity score, and
//! timestamp are stored in evidence. The actual text content from other windows
//! is never persisted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Default capacity for the rolling keystroke buffer (characters).
const DEFAULT_BUFFER_CAPACITY: usize = 500;

/// Default similarity threshold above which a match is flagged.
const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.70;

/// Default minimum match length (characters) to consider a match meaningful.
const DEFAULT_MIN_MATCH_LENGTH: usize = 100;

/// A detected cross-window transcription match.
///
/// Stored in evidence output. Never contains the actual matched text content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossWindowMatch {
    /// Name of the application that contained the matching text.
    pub source_app: String,
    /// Title of the window that contained the matching text.
    pub source_window_title: String,
    /// Similarity score in `[0.0, 1.0]`.
    pub similarity_score: f64,
    /// Number of characters in the best matching subsequence.
    pub matched_length: usize,
    /// When the match was detected.
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
/// Detects transcription by comparing typed content against other window text.
pub struct TranscriptionDetector {
    typing_buffer: VecDeque<char>,
    buffer_capacity: usize,
    similarity_threshold: f64,
    min_match_length: usize,
    matches: Vec<CrossWindowMatch>,
}

impl TranscriptionDetector {
    /// Create a detector with default configuration.
    pub fn new() -> Self {
        Self {
            typing_buffer: VecDeque::with_capacity(DEFAULT_BUFFER_CAPACITY),
            buffer_capacity: DEFAULT_BUFFER_CAPACITY,
            similarity_threshold: DEFAULT_SIMILARITY_THRESHOLD,
            min_match_length: DEFAULT_MIN_MATCH_LENGTH,
            matches: Vec::new(),
        }
    }

    /// Create a detector with custom configuration.
    pub fn with_config(
        buffer_capacity: usize,
        similarity_threshold: f64,
        min_match_length: usize,
    ) -> Self {
        Self {
            typing_buffer: VecDeque::with_capacity(buffer_capacity),
            buffer_capacity,
            similarity_threshold: crate::utils::Probability::clamp(similarity_threshold).get(),
            min_match_length,
            matches: Vec::new(),
        }
    }

    /// Record a typed character into the rolling buffer.
    pub fn record_keystroke(&mut self, ch: char) {
        if self.typing_buffer.len() >= self.buffer_capacity {
            self.typing_buffer.pop_front();
        }
        self.typing_buffer.push_back(ch);
    }

    /// Compare the current typing buffer against text from another window.
    ///
    /// Returns `Some(CrossWindowMatch)` if the similarity exceeds the threshold
    /// and the matched length exceeds `min_match_length`. The match is also
    /// appended to the internal match list.
    pub fn check_against_text(
        &mut self,
        text: &str,
        app_name: &str,
        window_title: &str,
    ) -> Option<CrossWindowMatch> {
        if self.typing_buffer.len() < self.min_match_length || text.len() < self.min_match_length {
            return None;
        }

        let typed: String = self.typing_buffer.iter().collect();
        let (score, matched_len) = best_substring_lcs_similarity(&typed, text);

        if score >= self.similarity_threshold && matched_len >= self.min_match_length {
            let m = CrossWindowMatch {
                source_app: app_name.to_string(),
                source_window_title: window_title.to_string(),
                similarity_score: score,
                matched_length: matched_len,
                detected_at: Utc::now(),
            };
            self.matches.push(m.clone());
            Some(m)
        } else {
            None
        }
    }

    /// Return all recorded matches.
    pub fn matches(&self) -> &[CrossWindowMatch] {
        &self.matches
    }

    /// Clear all recorded matches.
    pub fn clear_matches(&mut self) {
        self.matches.clear();
    }

    /// Return the current typing buffer length.
    pub fn buffer_len(&self) -> usize {
        self.typing_buffer.len()
    }

    /// Clear the typing buffer (e.g., on session reset).
    pub fn clear_buffer(&mut self) {
        self.typing_buffer.clear();
    }
}

impl Default for TranscriptionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the best LCS similarity between `typed` and any substring of `source`
/// of length close to `typed.len()`.
///
/// Uses a sliding window over `source` to find the best matching region, then
/// computes the LCS ratio within that window. Returns `(similarity_score, lcs_length)`.
fn best_substring_lcs_similarity(typed: &str, source: &str) -> (f64, usize) {
    let typed_chars: Vec<char> = typed.chars().collect();
    let source_chars: Vec<char> = source.chars().collect();

    if typed_chars.is_empty() || source_chars.is_empty() {
        return (0.0, 0);
    }

    let n = typed_chars.len();
    // Window size: look at regions slightly larger than the typed text to allow
    // for minor insertions/deletions in the source.
    let window_size = (n + n / 4).min(source_chars.len());
    let step = n / 4;
    let step = step.max(1);

    let mut best_score = 0.0;
    let mut best_len = 0;

    if source_chars.len() <= window_size {
        // Source is smaller than or equal to window; compare directly.
        let lcs_len = lcs_length(&typed_chars, &source_chars);
        let score = lcs_len as f64 / n as f64;
        return (score, lcs_len);
    }

    let mut offset = 0;
    while offset + window_size <= source_chars.len() {
        let window = &source_chars[offset..offset + window_size];
        let lcs_len = lcs_length(&typed_chars, window);
        let score = lcs_len as f64 / n as f64;
        if score > best_score {
            best_score = score;
            best_len = lcs_len;
        }
        // Early exit if we found a near-perfect match.
        if best_score > 0.95 {
            break;
        }
        offset += step;
    }

    // Check the tail window if we haven't covered it.
    if offset + window_size > source_chars.len() && offset < source_chars.len() {
        let tail_start = source_chars.len().saturating_sub(window_size);
        let window = &source_chars[tail_start..];
        let lcs_len = lcs_length(&typed_chars, window);
        let score = lcs_len as f64 / n as f64;
        if score > best_score {
            best_score = score;
            best_len = lcs_len;
        }
    }

    (best_score, best_len)
}

/// Compute the length of the longest common subsequence between two character slices.
///
/// Standard DP approach, O(n*m) time and O(min(n,m)) space using a rolling row.
fn lcs_length(a: &[char], b: &[char]) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }

    // Use the shorter sequence as columns for space efficiency.
    let (rows, cols) = if a.len() >= b.len() { (a, b) } else { (b, a) };

    let m = cols.len();
    let mut prev = vec![0u16; m + 1];
    let mut curr = vec![0u16; m + 1];

    for &r in rows {
        for (j, &c) in cols.iter().enumerate() {
            curr[j + 1] = if r == c {
                prev[j] + 1
            } else {
                prev[j + 1].max(curr[j])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.iter_mut().for_each(|x| *x = 0);
    }

    prev[m] as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lcs_identical() {
        let a: Vec<char> = "hello world".chars().collect();
        let len = lcs_length(&a, &a);
        assert_eq!(len, 11);
    }

    #[test]
    fn test_lcs_empty() {
        let a: Vec<char> = "hello".chars().collect();
        let b: Vec<char> = Vec::new();
        assert_eq!(lcs_length(&a, &b), 0);
        assert_eq!(lcs_length(&b, &a), 0);
    }

    #[test]
    fn test_lcs_no_common() {
        let a: Vec<char> = "abc".chars().collect();
        let b: Vec<char> = "xyz".chars().collect();
        assert_eq!(lcs_length(&a, &b), 0);
    }

    #[test]
    fn test_lcs_partial() {
        let a: Vec<char> = "abcde".chars().collect();
        let b: Vec<char> = "ace".chars().collect();
        assert_eq!(lcs_length(&a, &b), 3);
    }

    #[test]
    fn test_lcs_subsequence() {
        let a: Vec<char> = "The quick brown fox".chars().collect();
        let b: Vec<char> = "Tequick bfox".chars().collect();
        let len = lcs_length(&a, &b);
        // "Tequick bfox" is mostly a subsequence, LCS should be high.
        assert!(len >= 10);
    }

    #[test]
    fn test_detector_basic_no_match() {
        let mut detector = TranscriptionDetector::with_config(200, 0.70, 10);
        for ch in "hello world how are you".chars() {
            detector.record_keystroke(ch);
        }
        let result =
            detector.check_against_text("completely different text here", "Safari", "Google");
        assert!(result.is_none());
    }

    #[test]
    fn test_detector_exact_match() {
        let text = "The quick brown fox jumps over the lazy dog and then some more text to pad";
        let mut detector = TranscriptionDetector::with_config(200, 0.70, 10);
        for ch in text.chars() {
            detector.record_keystroke(ch);
        }
        let result = detector.check_against_text(text, "TextEdit", "notes.txt");
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(m.similarity_score > 0.95);
        assert_eq!(m.source_app, "TextEdit");
        assert_eq!(m.source_window_title, "notes.txt");
    }

    #[test]
    fn test_detector_high_similarity() {
        // Typed with a few typos but mostly the same.
        let source = "The quick brown fox jumps over the lazy dog and keeps running";
        let typed = "The quikc brown fox jumps over teh lazy dog and keeps running";
        let mut detector = TranscriptionDetector::with_config(200, 0.70, 10);
        for ch in typed.chars() {
            detector.record_keystroke(ch);
        }
        let result = detector.check_against_text(source, "Safari", "Wikipedia");
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(m.similarity_score >= 0.70);
    }

    #[test]
    fn test_detector_below_threshold() {
        let mut detector = TranscriptionDetector::with_config(200, 0.70, 10);
        for ch in "completely original content that is not at all similar".chars() {
            detector.record_keystroke(ch);
        }
        let result = detector.check_against_text(
            "unrelated text about different topics entirely here now",
            "Safari",
            "Reddit",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_detector_buffer_rolls() {
        let mut detector = TranscriptionDetector::with_config(10, 0.70, 5);
        for ch in "abcdefghijklmnop".chars() {
            detector.record_keystroke(ch);
        }
        // Buffer should only contain the last 10 chars.
        assert_eq!(detector.buffer_len(), 10);
    }

    #[test]
    fn test_detector_too_short() {
        let mut detector = TranscriptionDetector::with_config(200, 0.70, 50);
        for ch in "short".chars() {
            detector.record_keystroke(ch);
        }
        // Buffer too short for min_match_length.
        let result = detector.check_against_text("short text too", "App", "Win");
        assert!(result.is_none());
    }

    #[test]
    fn test_matches_accumulate() {
        let text = "The quick brown fox jumps over the lazy dog and then some more padding";
        let mut detector = TranscriptionDetector::with_config(200, 0.70, 10);
        for ch in text.chars() {
            detector.record_keystroke(ch);
        }
        detector.check_against_text(text, "App1", "Win1");
        detector.check_against_text(text, "App2", "Win2");
        assert_eq!(detector.matches().len(), 2);
        detector.clear_matches();
        assert!(detector.matches().is_empty());
    }

    #[test]
    fn test_substring_match_in_longer_source() {
        // Source has the typed text embedded in a larger document.
        let typed = "four score and seven years ago our fathers brought forth";
        let source = "Preamble text here. four score and seven years ago our fathers brought forth on this continent a new nation. More text follows.";
        let mut detector = TranscriptionDetector::with_config(200, 0.70, 10);
        for ch in typed.chars() {
            detector.record_keystroke(ch);
        }
        let result = detector.check_against_text(source, "Preview", "speech.pdf");
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(m.similarity_score > 0.90);
    }

    #[test]
    fn test_best_substring_similarity_identical() {
        let (score, len) = best_substring_lcs_similarity("abcdef", "abcdef");
        assert!((score - 1.0).abs() < f64::EPSILON);
        assert_eq!(len, 6);
    }

    #[test]
    fn test_best_substring_similarity_empty() {
        let (score, _) = best_substring_lcs_similarity("", "abcdef");
        assert_eq!(score, 0.0);
        let (score, _) = best_substring_lcs_similarity("abcdef", "");
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_default_detector() {
        let det = TranscriptionDetector::default();
        assert_eq!(det.buffer_len(), 0);
        assert!(det.matches().is_empty());
    }
}
