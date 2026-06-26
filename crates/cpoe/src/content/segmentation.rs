// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Content segmentation for content-level witnessing.
//!
//! Splits text into segments (paragraphs, sentences, or blocks) and produces
//! normalized SHA-256 hashes for each. Used by the content MMR to build
//! paragraph-level Merkle trees that survive format conversions (XML → HTML →
//! Word) while preserving privacy of non-exported content.

use crate::ffi::text_fragment::normalize_for_attestation;
use crate::sentinel::app_registry::ContentGranularity;
use sha2::{Digest, Sha256};

/// Domain separation tag for content segment hashes.
const CONTENT_SEGMENT_DST: &[u8] = b"witnessd-content-segment-v1";

#[derive(Debug, Clone)]
pub struct ContentSegment {
    pub index: usize,
    pub raw_text: String,
    /// SHA-256(DST || normalized text). Used as the MMR leaf value.
    pub hash: [u8; 32],
}

/// Segment text according to the given granularity and compute normalized
/// hashes for each segment. Empty segments are filtered out.
pub fn segment_and_hash(text: &str, granularity: ContentGranularity) -> Vec<ContentSegment> {
    let raw_segments = split_text(text, granularity);
    raw_segments
        .into_iter()
        .enumerate()
        .filter_map(|(i, raw)| {
            let normalized = normalize_for_attestation(&raw);
            if normalized.is_empty() {
                return None;
            }
            let hash = hash_segment(&normalized);
            Some(ContentSegment {
                index: i,
                raw_text: raw,
                hash,
            })
        })
        .collect()
}

fn hash_segment(normalized: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_SEGMENT_DST);
    hasher.update(normalized.as_bytes());
    hasher.finalize().into()
}

fn split_text(text: &str, granularity: ContentGranularity) -> Vec<String> {
    match granularity {
        ContentGranularity::Paragraph => split_paragraphs(text),
        ContentGranularity::Sentence => split_sentences(text),
        ContentGranularity::Block => split_blocks(text),
    }
}

fn split_paragraphs(text: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current = String::new();

    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.trim().is_empty() {
                paragraphs.push(std::mem::take(&mut current));
            }
            current.clear();
        } else {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(line.trim());
        }
    }
    if !current.trim().is_empty() {
        paragraphs.push(current);
    }
    paragraphs
}

/// Split on sentence boundaries. Handles `.`, `?`, `!` followed by whitespace
/// or end-of-string. Does not break on abbreviations like "Dr." or "U.S."
/// (best-effort heuristic, not NLP-grade).
fn split_sentences(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();

    let mut i = 0;
    while i < len {
        let c = chars[i];
        current.push(c);

        if (c == '.' || c == '?' || c == '!') && is_sentence_end(&chars, i) {
            let trimmed = current.trim().to_string();
            if !trimmed.is_empty() {
                sentences.push(trimmed);
            }
            current.clear();
        }
        i += 1;
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        sentences.push(trimmed);
    }
    sentences
}

/// Common abbreviations that end with '.' but do not end a sentence.
const ABBREVIATIONS: &[&str] = &[
    "Dr", "Mr", "Mrs", "Ms", "Prof", "Sr", "Jr", "St", "Rev", "Gen", "Gov", "Sgt", "Cpl", "Pvt",
    "Lt", "Col", "Capt", "Cmdr", "Adm", "Maj", "vs", "etc", "approx", "dept", "est", "vol", "no",
    "i.e", "e.g", "cf", "al",
];

/// Check if the word immediately before position `i` (a '.') is a known abbreviation.
fn is_abbreviation(chars: &[char], dot_pos: usize) -> bool {
    let mut end = dot_pos;
    // Walk back past any inner dots (for "i.e.", "e.g.")
    while end > 0 && (chars[end - 1].is_alphanumeric() || chars[end - 1] == '.') {
        end -= 1;
    }
    let word: String = chars[end..dot_pos].iter().collect();
    // Strip inner dots for comparison ("i.e" → "ie" won't match, but we keep "i.e" in the list)
    ABBREVIATIONS
        .iter()
        .any(|&abbr| word.eq_ignore_ascii_case(abbr))
}

/// Check if position `i` (a sentence-ending punctuation) is likely a real
/// sentence boundary: followed by whitespace+uppercase, end-of-string, or
/// closing quote then whitespace.
fn is_sentence_end(chars: &[char], i: usize) -> bool {
    let len = chars.len();
    // End of string
    if i + 1 >= len {
        return true;
    }
    // Known abbreviation → not a sentence boundary
    if chars[i] == '.' && is_abbreviation(chars, i) {
        return false;
    }
    let next = chars[i + 1];
    // Closing quote/paren after punctuation
    if next == '"' || next == '\'' || next == ')' || next == '\u{201D}' {
        return i + 2 >= len || chars[i + 2].is_whitespace();
    }
    // Not followed by whitespace → probably abbreviation
    if !next.is_whitespace() {
        return false;
    }
    // Whitespace followed by uppercase or end → sentence boundary
    if i + 2 >= len {
        return true;
    }
    let after_space = chars[i + 2];
    after_space.is_uppercase() || after_space == '"' || after_space == '\u{201C}'
}

fn split_blocks(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Match segments from a source document against segments from a derived
/// document. Returns indices of source segments that appear in the derived
/// document, enabling derivation proofs without exposing the full source.
pub fn match_segments(source: &[ContentSegment], derived: &[ContentSegment]) -> Vec<SegmentMatch> {
    use std::collections::HashMap;
    let source_map: HashMap<[u8; 32], &ContentSegment> =
        source.iter().map(|s| (s.hash, s)).collect();
    let mut matches = Vec::new();
    for d in derived {
        if let Some(s) = source_map.get(&d.hash) {
            matches.push(SegmentMatch {
                source_index: s.index,
                derived_index: d.index,
                hash: s.hash,
            });
        }
    }
    matches
}

#[derive(Debug, Clone)]
pub struct SegmentMatch {
    pub source_index: usize,
    pub derived_index: usize,
    pub hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paragraph_splitting() {
        let text = "First paragraph here.\n\nSecond paragraph here.\n\nThird one.";
        let segments = segment_and_hash(text, ContentGranularity::Paragraph);
        assert_eq!(segments.len(), 3);
        assert!(segments[0].raw_text.contains("First"));
        assert!(segments[1].raw_text.contains("Second"));
        assert!(segments[2].raw_text.contains("Third"));
    }

    #[test]
    fn test_sentence_splitting() {
        let text = "Hello world. This is a test. How are you? Fine!";
        let segments = segment_and_hash(text, ContentGranularity::Sentence);
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0].raw_text, "Hello world.");
        assert_eq!(segments[1].raw_text, "This is a test.");
    }

    #[test]
    fn test_block_splitting() {
        let text = "line one\nline two\n\nline three\n";
        let segments = segment_and_hash(text, ContentGranularity::Block);
        assert_eq!(segments.len(), 3);
    }

    #[test]
    fn test_empty_segments_filtered() {
        let text = "\n\n\n   \n\nHello\n\n";
        let segments = segment_and_hash(text, ContentGranularity::Paragraph);
        assert_eq!(segments.len(), 1);
    }

    #[test]
    fn test_normalization_makes_hashes_format_independent() {
        // Same content with different formatting should produce same hash
        let text_a = "Hello, World!";
        let text_b = "hello, world!"; // different case
        let hash_a = hash_segment(&normalize_for_attestation(text_a));
        let hash_b = hash_segment(&normalize_for_attestation(text_b));
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_segment_matching() {
        let source_text = "Para one.\n\nPara two.\n\nPara three.";
        let derived_text = "Para two.\n\nPara three.\n\nNew para.";
        let source = segment_and_hash(source_text, ContentGranularity::Paragraph);
        let derived = segment_and_hash(derived_text, ContentGranularity::Paragraph);
        let matches = match_segments(&source, &derived);
        assert_eq!(matches.len(), 2); // "Para two" and "Para three"
        let coverage = matches.len() as f64 / derived.len() as f64;
        assert!((coverage - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_domain_separation() {
        // Raw SHA-256 of normalized text should differ from domain-separated hash
        let text = "test content";
        let normalized = normalize_for_attestation(text);
        let raw_hash: [u8; 32] = Sha256::digest(normalized.as_bytes()).into();
        let seg_hash = hash_segment(&normalized);
        assert_ne!(raw_hash, seg_hash);
    }

    #[test]
    fn test_sentence_abbreviation_handling() {
        let text = "Dr. Smith went to Washington. He arrived at noon.";
        let segments = segment_and_hash(text, ContentGranularity::Sentence);
        // "Dr." should not split — only 2 sentences
        assert_eq!(segments.len(), 2);
    }

    #[test]
    fn test_multiline_paragraph_joins() {
        let text = "Line one of para.\nLine two of para.\n\nSecond para.";
        let segments = segment_and_hash(text, ContentGranularity::Paragraph);
        assert_eq!(segments.len(), 2);
        assert!(segments[0].raw_text.contains("Line one"));
        assert!(segments[0].raw_text.contains("Line two"));
    }
}
