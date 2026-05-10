// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! SimHash-based content fingerprinting for cross-app session linking.
//!
//! When a user edits the same document in different apps (e.g., exports from
//! Scrivener to Word, or opens the same `.md` in VS Code then Obsidian), each
//! app creates a separate session.  This module computes a locality-sensitive
//! fingerprint of the document content so that sessions with highly similar
//! content can be linked into a single authorship chain.
//!
//! The fingerprint is a 64-bit SimHash of character 4-grams.  Documents with
//! small edits produce fingerprints with low Hamming distance, while unrelated
//! documents diverge quickly.

use std::time::SystemTime;

/// A locality-sensitive fingerprint of document content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentFingerprint {
    /// 64-bit SimHash of character 4-grams.
    pub simhash: u64,
    /// Total character count of the source text.
    pub char_count: usize,
    /// Total word count of the source text.
    pub word_count: usize,
}

/// Hamming distance threshold for considering two documents "similar".
/// With 64-bit SimHash, distance <= 10 corresponds to ~84% bit agreement.
const SIMILARITY_THRESHOLD: u32 = 11;

/// Minimum character count for a meaningful fingerprint comparison.
/// Very short documents produce unreliable SimHash values.
const MIN_CHARS_FOR_COMPARISON: usize = 50;

impl ContentFingerprint {
    /// Compute a fingerprint from document text.
    ///
    /// The text is decomposed into overlapping character 4-grams, each hashed
    /// to a 64-bit value.  The SimHash algorithm aggregates these hashes into
    /// a single 64-bit fingerprint where each bit represents the majority vote
    /// across all n-gram hashes.
    pub fn from_text(text: &str) -> Self {
        let char_count = text.chars().count();
        let word_count = text.split_whitespace().count();

        if char_count < 4 {
            return Self {
                simhash: 0,
                char_count,
                word_count,
            };
        }

        // Streaming 4-gram extraction without allocating the full char vector.
        let mut bit_counts = [0i32; 64];
        let mut ring = ['\0'; 4];
        let mut ring_len = 0usize;

        for ch in text.chars() {
            ring[ring_len % 4] = ch;
            ring_len += 1;
            if ring_len >= 4 {
                let start = ring_len % 4;
                let ngram = [
                    ring[start % 4],
                    ring[(start + 1) % 4],
                    ring[(start + 2) % 4],
                    ring[(start + 3) % 4],
                ];
                let hash = hash_ngram(&ngram);
                for (i, count) in bit_counts.iter_mut().enumerate() {
                    if hash & (1u64 << i) != 0 {
                        *count += 1;
                    } else {
                        *count -= 1;
                    }
                }
            }
        }

        let mut simhash = 0u64;
        for (i, &count) in bit_counts.iter().enumerate() {
            if count > 0 {
                simhash |= 1u64 << i;
            }
        }

        Self {
            simhash,
            char_count,
            word_count,
        }
    }

    /// Hamming distance between two fingerprints (0 = identical, 64 = opposite).
    pub fn distance(&self, other: &Self) -> u32 {
        (self.simhash ^ other.simhash).count_ones()
    }

    /// Returns `true` if two fingerprints are similar enough to represent the
    /// same document (possibly with minor edits).
    ///
    /// Returns `false` if either document is too short for reliable comparison.
    pub fn is_similar(&self, other: &Self) -> bool {
        if self.char_count < MIN_CHARS_FOR_COMPARISON
            || other.char_count < MIN_CHARS_FOR_COMPARISON
        {
            return false;
        }
        self.distance(other) < SIMILARITY_THRESHOLD
    }
}

/// A detected link between two sessions editing similar content in different apps.
#[derive(Debug, Clone)]
pub struct CrossAppLink {
    /// Session ID of the first session.
    pub session_a_id: String,
    /// Session ID of the second session.
    pub session_b_id: String,
    /// Application bundle ID of the first session.
    pub app_a: String,
    /// Application bundle ID of the second session.
    pub app_b: String,
    /// Hamming distance between the two content fingerprints.
    pub fingerprint_distance: u32,
    /// When the link was detected.
    pub detected_at: SystemTime,
}

/// Try to find a cross-app match for a new session's content fingerprint
/// among existing sessions.
///
/// Returns a `CrossAppLink` if a session in a *different* app has similar
/// content.  Sessions in the same app are skipped (those are likely the same
/// document reopened, already handled by path matching).
pub fn find_cross_app_match(
    new_session_id: &str,
    new_app: &str,
    new_fingerprint: &ContentFingerprint,
    existing: &[(String, String, ContentFingerprint)], // (session_id, app_bundle_id, fingerprint)
) -> Option<CrossAppLink> {
    let mut best: Option<(u32, usize)> = None;

    for (i, (_, app, fp)) in existing.iter().enumerate() {
        // Skip same-app sessions.
        if app == new_app {
            continue;
        }
        if !new_fingerprint.is_similar(fp) {
            continue;
        }
        let dist = new_fingerprint.distance(fp);
        if best.map_or(true, |(d, _)| dist < d) {
            best = Some((dist, i));
        }
    }

    best.map(|(dist, idx)| {
        let (ref sid, ref app, _) = existing[idx];
        CrossAppLink {
            session_a_id: sid.clone(),
            session_b_id: new_session_id.to_string(),
            app_a: app.clone(),
            app_b: new_app.to_string(),
            fingerprint_distance: dist,
            detected_at: SystemTime::now(),
        }
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// FNV-1a hash of a character n-gram, producing a 64-bit value.
///
/// FNV-1a is chosen for speed and simplicity; cryptographic strength is not
/// needed for SimHash feature hashing.
fn hash_ngram(ngram: &[char]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for &ch in ngram {
        // Hash each byte of the UTF-8 encoding.
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        for &byte in encoded.as_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_text_zero_distance() {
        let text = "The quick brown fox jumps over the lazy dog. This is a longer sentence for testing.";
        let fp1 = ContentFingerprint::from_text(text);
        let fp2 = ContentFingerprint::from_text(text);
        assert_eq!(fp1.distance(&fp2), 0);
        assert_eq!(fp1.simhash, fp2.simhash);
    }

    #[test]
    fn test_minor_edit_small_distance() {
        let text1 =
            "The quick brown fox jumps over the lazy dog. This is a test of content fingerprinting.";
        let text2 =
            "The quick brown fox leaps over the lazy dog. This is a test of content fingerprinting.";
        let fp1 = ContentFingerprint::from_text(text1);
        let fp2 = ContentFingerprint::from_text(text2);
        let dist = fp1.distance(&fp2);
        assert!(
            dist < SIMILARITY_THRESHOLD,
            "minor edit should produce small distance, got {dist}"
        );
    }

    #[test]
    fn test_different_documents_large_distance() {
        let text1 = "The principles of quantum mechanics govern the behavior of subatomic particles \
                      in ways that challenge our classical intuition about the physical world.";
        let text2 = "Chocolate chip cookies require flour, sugar, butter, eggs, and vanilla extract. \
                      Preheat the oven to three hundred and fifty degrees before mixing ingredients.";
        let fp1 = ContentFingerprint::from_text(text1);
        let fp2 = ContentFingerprint::from_text(text2);
        let dist = fp1.distance(&fp2);
        assert!(
            dist > SIMILARITY_THRESHOLD,
            "different documents should produce large distance, got {dist}"
        );
    }

    #[test]
    fn test_short_text_not_similar() {
        let fp1 = ContentFingerprint::from_text("hi");
        let fp2 = ContentFingerprint::from_text("hi");
        // Too short for reliable comparison.
        assert!(!fp1.is_similar(&fp2));
    }

    #[test]
    fn test_empty_text() {
        let fp = ContentFingerprint::from_text("");
        assert_eq!(fp.simhash, 0);
        assert_eq!(fp.char_count, 0);
        assert_eq!(fp.word_count, 0);
    }

    #[test]
    fn test_word_count() {
        let fp = ContentFingerprint::from_text("hello world foo bar");
        assert_eq!(fp.word_count, 4);
        assert_eq!(fp.char_count, 19);
    }

    #[test]
    fn test_unicode_text() {
        let text = "日本語のテスト文章です。これは内容のフィンガープリントをテストするための長い文章です。";
        let fp = ContentFingerprint::from_text(text);
        assert!(fp.char_count > 0);
        assert!(fp.simhash != 0);
    }

    #[test]
    fn test_cross_app_match_found() {
        let text = "A long document about software engineering practices and design patterns \
                    that spans multiple paragraphs for reliable fingerprinting.";
        let text_edited = "A long document about software engineering practices and design patterns \
                           that spans several paragraphs for reliable fingerprinting.";

        let fp_existing = ContentFingerprint::from_text(text);
        let fp_new = ContentFingerprint::from_text(text_edited);

        let existing = vec![(
            "session-1".to_string(),
            "com.apple.Pages".to_string(),
            fp_existing,
        )];

        let link = find_cross_app_match("session-2", "com.microsoft.Word", &fp_new, &existing);
        assert!(link.is_some(), "should find cross-app match");
        let link = link.unwrap();
        assert_eq!(link.session_a_id, "session-1");
        assert_eq!(link.session_b_id, "session-2");
    }

    #[test]
    fn test_cross_app_match_same_app_skipped() {
        let text = "A long document about software engineering practices and design patterns \
                    that spans multiple paragraphs for reliable fingerprinting.";
        let fp = ContentFingerprint::from_text(text);

        let existing = vec![(
            "session-1".to_string(),
            "com.apple.Pages".to_string(),
            fp,
        )];

        // Same app — should NOT match.
        let link = find_cross_app_match("session-2", "com.apple.Pages", &fp, &existing);
        assert!(link.is_none(), "same-app sessions should not match");
    }

    #[test]
    fn test_cross_app_match_not_similar() {
        let fp1 = ContentFingerprint::from_text(
            "The principles of quantum mechanics are fascinating and deeply counterintuitive \
             to most people who study them for the first time.",
        );
        let fp2 = ContentFingerprint::from_text(
            "Chocolate chip cookies need flour, sugar, butter, and eggs. Mix thoroughly and \
             bake at three hundred fifty degrees for twelve minutes.",
        );

        let existing = vec![(
            "session-1".to_string(),
            "com.apple.Pages".to_string(),
            fp1,
        )];

        let link = find_cross_app_match("session-2", "com.microsoft.Word", &fp2, &existing);
        assert!(link.is_none(), "dissimilar content should not match");
    }
}
